//! Comprehensive unit tests for vaultkeeper-core.
//!
//! @see RFC 7516 (JWE Compact Serialization)
//! @see RFC 5116 (AES-GCM)

use vaultkeeper_core::backend::{BackendRegistry, ExecOutput, HostPlatform, Platform};
use vaultkeeper_core::config::{default_config, load_config_from_str, validate_config};
use vaultkeeper_core::errors::{ExecutableTrustRequiredReason, VaultError};
use vaultkeeper_core::keys::KeyManager;
use vaultkeeper_core::types::{
    BackendConfig, DevelopmentMode, KeyRotationPolicy, KeyStatus, SecretAccessor, TrustTier,
    VaultClaims, VaultConfig, VaultDefaults, VaultResponse,
};
use vaultkeeper_core::vault::VaultKeeperOptions;
use vaultkeeper_core::{InMemoryBackend, VaultKeeper};

// ---------------------------------------------------------------------------
// Config validation tests
// ---------------------------------------------------------------------------

mod config_validation {
    use super::*;

    #[test]
    fn default_config_is_valid() {
        let cfg = default_config();
        assert!(validate_config(&cfg).is_ok());
        assert_eq!(cfg.version, 1);
        assert_eq!(cfg.backends.len(), 1);
        assert!(cfg.backends[0].enabled);
    }

    #[test]
    fn default_config_uses_platform_appropriate_backend() {
        let cfg = default_config();
        let backend_type = cfg.backends[0].backend_type.as_str();
        // On Linux (where CI runs), 'keychain' is macOS-only and must not be the default.
        #[cfg(not(target_os = "macos"))]
        assert_ne!(backend_type, "keychain", "keychain is macOS-only");
        // On macOS, keychain is the expected default.
        #[cfg(target_os = "macos")]
        assert_eq!(backend_type, "keychain");
        // On Windows, dpapi is the expected default.
        #[cfg(target_os = "windows")]
        assert_eq!(backend_type, "dpapi");
        // On Linux and other Unix, file is the expected default.
        #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
        assert_eq!(backend_type, "file");
    }

    #[test]
    fn default_config_has_no_path_field() {
        // The file backend manages its own storage location; the path field
        // in config is ignored. Generating a path in the default config would
        // be misleading (~ is not expanded by the backend either).
        let cfg = default_config();
        assert!(cfg.backends[0].path.is_none());
    }

    #[test]
    fn rejects_wrong_version() {
        let mut cfg = default_config();
        cfg.version = 2;
        assert!(validate_config(&cfg).is_err());
    }

    #[test]
    fn rejects_empty_backends() {
        let mut cfg = default_config();
        cfg.backends = vec![];
        assert!(validate_config(&cfg).is_err());
    }

    #[test]
    fn rejects_empty_backend_type() {
        let mut cfg = default_config();
        cfg.backends[0].backend_type = "  ".to_string();
        assert!(validate_config(&cfg).is_err());
    }

    #[test]
    fn rejects_zero_grace_period() {
        let mut cfg = default_config();
        cfg.key_rotation.grace_period_days = 0;
        assert!(validate_config(&cfg).is_err());
    }

    #[test]
    fn rejects_zero_ttl() {
        let mut cfg = default_config();
        cfg.defaults.ttl_minutes = 0;
        assert!(validate_config(&cfg).is_err());
    }

    #[test]
    fn accepts_valid_dev_mode() {
        let mut cfg = default_config();
        cfg.development_mode = Some(DevelopmentMode {
            executables: vec!["/usr/bin/node".to_string()],
        });
        assert!(validate_config(&cfg).is_ok());
    }

    #[test]
    fn rejects_empty_dev_mode_executable() {
        let mut cfg = default_config();
        cfg.development_mode = Some(DevelopmentMode {
            executables: vec!["  ".to_string()],
        });
        assert!(validate_config(&cfg).is_err());
    }

    #[test]
    fn load_config_from_empty_string_returns_default() {
        let cfg = load_config_from_str("").unwrap();
        assert_eq!(cfg.version, 1);
    }

    #[test]
    fn load_config_from_valid_json() {
        let json = r#"{
            "version": 1,
            "backends": [{"type": "keychain", "enabled": true}],
            "keyRotation": {"gracePeriodDays": 14},
            "defaults": {"ttlMinutes": 120, "trustTier": "2"}
        }"#;
        let cfg = load_config_from_str(json).unwrap();
        assert_eq!(cfg.backends[0].backend_type, "keychain");
        assert_eq!(cfg.key_rotation.grace_period_days, 14);
        assert_eq!(cfg.defaults.ttl_minutes, 120);
        assert_eq!(cfg.defaults.trust_tier, TrustTier::Tofu);
    }

    #[test]
    fn load_config_from_invalid_json_errors() {
        let result = load_config_from_str("{invalid");
        assert!(result.is_err());
    }
}

// ---------------------------------------------------------------------------
// Type serialization round-trip tests
// ---------------------------------------------------------------------------

mod type_serde {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn vault_claims_round_trip() {
        let claims = VaultClaims {
            jti: "abc-123".to_string(),
            exp: 1700000000,
            iat: 1699996400,
            sub: "db-password".to_string(),
            exe: "dev".to_string(),
            use_limit: Some(5),
            tid: TrustTier::Tofu,
            bkd: "keychain".to_string(),
            val: "super-secret".to_string(),
            reference: "db-password".to_string(),
        };

        let json = serde_json::to_string(&claims).unwrap();
        let decoded: VaultClaims = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.jti, claims.jti);
        assert_eq!(decoded.use_limit, Some(5));
        assert_eq!(decoded.tid, TrustTier::Tofu);
    }

    #[test]
    fn vault_claims_null_use_limit() {
        let claims = VaultClaims {
            jti: "xyz".to_string(),
            exp: 1700000000,
            iat: 1699996400,
            sub: "key".to_string(),
            exe: "dev".to_string(),
            use_limit: None,
            tid: TrustTier::Dev,
            bkd: "file".to_string(),
            val: "secret".to_string(),
            reference: "key".to_string(),
        };

        let json = serde_json::to_string(&claims).unwrap();
        assert!(json.contains("null"));

        let decoded: VaultClaims = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.use_limit, None);
    }

    #[test]
    fn trust_tier_serializes_as_string_number() {
        let tier = TrustTier::Sigstore;
        let json = serde_json::to_string(&tier).unwrap();
        assert_eq!(json, "\"1\"");

        let decoded: TrustTier = serde_json::from_str("\"3\"").unwrap();
        assert_eq!(decoded, TrustTier::Dev);
    }

    #[test]
    fn key_status_serializes_lowercase() {
        let status = KeyStatus::Current;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, "\"current\"");
    }

    #[test]
    fn vault_config_round_trip() {
        let cfg = VaultConfig {
            version: 1,
            backends: vec![BackendConfig {
                backend_type: "file".to_string(),
                enabled: true,
                plugin: None,
                path: Some("/tmp/vault".to_string()),
                options: Some(HashMap::from([(
                    "algo".to_string(),
                    "aes-256-gcm".to_string(),
                )])),
            }],
            key_rotation: KeyRotationPolicy {
                grace_period_days: 7,
            },
            defaults: VaultDefaults {
                ttl_minutes: 60,
                trust_tier: TrustTier::Dev,
            },
            development_mode: None,
        };

        let json = serde_json::to_string(&cfg).unwrap();
        let decoded: VaultConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.version, 1);
        assert_eq!(decoded.backends[0].path, Some("/tmp/vault".to_string()));
    }

    #[test]
    fn vault_response_omits_none_rotated_jwt() {
        let response = VaultResponse {
            rotated_jwt: None,
            key_status: KeyStatus::Current,
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(!json.contains("rotatedJwt"));
    }

    #[test]
    fn vault_response_includes_rotated_jwt() {
        let response = VaultResponse {
            rotated_jwt: Some("new-jwe".to_string()),
            key_status: KeyStatus::Previous,
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("new-jwe"));
    }
}

// ---------------------------------------------------------------------------
// SecretAccessor tests
// ---------------------------------------------------------------------------

mod secret_accessor {
    use super::*;

    #[test]
    fn read_once_succeeds() {
        let mut accessor = SecretAccessor::new(b"my-secret".to_vec());
        let result = accessor.read(|buf| {
            assert_eq!(buf, b"my-secret");
            42
        });
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn second_read_fails() {
        let mut accessor = SecretAccessor::new(b"secret".to_vec());
        accessor.read(|_| ()).unwrap();

        let result = accessor.read(|_| ());
        assert!(result.is_err());
    }

    #[test]
    fn empty_secret() {
        let mut accessor = SecretAccessor::new(vec![]);
        let result = accessor.read(|buf| {
            assert!(buf.is_empty());
        });
        assert!(result.is_ok());
    }
}

// ---------------------------------------------------------------------------
// KeyManager tests
// ---------------------------------------------------------------------------

mod key_manager {
    use super::*;

    #[test]
    fn init_creates_current_key() {
        let mut km = KeyManager::new();
        km.init().unwrap();

        let key = km.get_current_key().unwrap();
        assert_eq!(key.key.len(), 32);
        assert!(key.id.starts_with("k-"));
    }

    #[test]
    fn no_previous_key_after_init() {
        let mut km = KeyManager::new();
        km.init().unwrap();
        assert!(km.get_previous_key().is_none());
    }

    #[test]
    fn rotate_creates_new_current_and_keeps_previous() {
        let mut km = KeyManager::new();
        km.init().unwrap();

        let original_id = km.get_current_key().unwrap().id.clone();
        km.rotate_key(86400000).unwrap();

        let new_id = km.get_current_key().unwrap().id.clone();
        assert_ne!(original_id, new_id);

        let prev = km.get_previous_key().unwrap();
        assert_eq!(prev.id, original_id);
    }

    #[test]
    fn double_rotate_fails() {
        let mut km = KeyManager::new();
        km.init().unwrap();
        km.rotate_key(86400000).unwrap();

        let result = km.rotate_key(86400000);
        assert!(matches!(result, Err(VaultError::RotationInProgress { .. })));
    }

    #[test]
    fn revoke_clears_previous_and_generates_new() {
        let mut km = KeyManager::new();
        km.init().unwrap();

        let id_before = km.get_current_key().unwrap().id.clone();
        km.rotate_key(86400000).unwrap();
        km.revoke_key().unwrap();

        assert!(km.get_previous_key().is_none());
        let id_after = km.get_current_key().unwrap().id.clone();
        assert_ne!(id_before, id_after);
    }

    #[test]
    fn find_key_by_id_finds_current() {
        let mut km = KeyManager::new();
        km.init().unwrap();

        let kid = km.get_current_key().unwrap().id.clone();
        let (found, is_current) = km.find_key_by_id(&kid).unwrap();
        assert_eq!(found.id, kid);
        assert!(is_current);
    }

    #[test]
    fn find_key_by_id_finds_previous() {
        let mut km = KeyManager::new();
        km.init().unwrap();

        let old_id = km.get_current_key().unwrap().id.clone();
        km.rotate_key(86400000).unwrap();

        let (found, is_current) = km.find_key_by_id(&old_id).unwrap();
        assert_eq!(found.id, old_id);
        assert!(!is_current);
    }

    #[test]
    fn find_key_by_id_returns_none_for_unknown() {
        let mut km = KeyManager::new();
        km.init().unwrap();
        assert!(km.find_key_by_id("k-nonexistent").is_none());
    }

    #[test]
    fn uninitialized_key_manager_errors() {
        let km = KeyManager::new();
        assert!(km.get_current_key().is_err());
    }
}

// ---------------------------------------------------------------------------
// BackendRegistry tests
// ---------------------------------------------------------------------------

mod backend_registry {
    use super::*;

    #[test]
    fn register_and_create() {
        let registry = BackendRegistry::new();
        registry.register("memory", |_| Box::new(InMemoryBackend::new()));

        assert!(registry.has("memory"));
        let backend = registry.create("memory", None).unwrap();
        assert_eq!(backend.backend_type(), "memory");
    }

    #[test]
    fn create_unknown_type_fails() {
        let registry = BackendRegistry::new();
        let result = registry.create("nonexistent", None);
        assert!(matches!(result, Err(VaultError::BackendUnavailable { .. })));
    }

    #[test]
    fn has_returns_false_for_unregistered() {
        let registry = BackendRegistry::new();
        assert!(!registry.has("missing"));
    }
}

// ---------------------------------------------------------------------------
// Error hierarchy tests
// ---------------------------------------------------------------------------

mod error_tests {
    use super::*;

    #[test]
    fn vault_error_displays_message() {
        let err = VaultError::SecretNotFound {
            message: "Key abc not found".to_string(),
        };
        assert_eq!(err.to_string(), "Key abc not found");
    }

    #[test]
    fn backend_locked_has_interactive_field() {
        let err = VaultError::BackendLocked {
            message: "Locked".to_string(),
            interactive: true,
        };
        if let VaultError::BackendLocked { interactive, .. } = err {
            assert!(interactive);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn identity_mismatch_carries_hashes() {
        let err = VaultError::IdentityMismatch {
            message: "mismatch".to_string(),
            previous_hash: "aaa".to_string(),
            current_hash: "bbb".to_string(),
        };
        if let VaultError::IdentityMismatch {
            previous_hash,
            current_hash,
            ..
        } = err
        {
            assert_eq!(previous_hash, "aaa");
            assert_eq!(current_hash, "bbb");
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn other_variant_wraps_arbitrary_message() {
        let err = VaultError::Other("something went wrong".to_string());
        assert_eq!(err.to_string(), "something went wrong");
    }

    #[test]
    fn all_variants_implement_display() {
        // Ensure no panic when formatting every variant
        let errors: Vec<VaultError> = vec![
            VaultError::BackendLocked {
                message: "m".into(),
                interactive: false,
            },
            VaultError::DeviceNotPresent {
                message: "m".into(),
                timeout_ms: 1000,
            },
            VaultError::AuthorizationDenied {
                message: "m".into(),
            },
            VaultError::BackendUnavailable {
                message: "m".into(),
                reason: "r".into(),
                attempted: vec![],
            },
            VaultError::PluginNotFound {
                message: "m".into(),
                plugin: "p".into(),
                install_url: "u".into(),
            },
            VaultError::SecretNotFound {
                message: "m".into(),
            },
            VaultError::Decryption {
                message: "m".into(),
                path: "p".into(),
            },
            VaultError::TokenExpired {
                message: "m".into(),
                can_refresh: true,
            },
            VaultError::KeyRotated {
                message: "m".into(),
            },
            VaultError::KeyRevoked {
                message: "m".into(),
            },
            VaultError::TokenRevoked {
                message: "m".into(),
            },
            VaultError::UsageLimitExceeded {
                message: "m".into(),
            },
            VaultError::IdentityMismatch {
                message: "m".into(),
                previous_hash: "a".into(),
                current_hash: "b".into(),
            },
            VaultError::InvalidAlgorithm {
                message: "m".into(),
                algorithm: "a".into(),
                allowed: vec![],
            },
            VaultError::Setup {
                message: "m".into(),
                dependency: "d".into(),
            },
            VaultError::Filesystem {
                message: "m".into(),
                path: "p".into(),
                permission: "w".into(),
            },
            VaultError::RotationInProgress {
                message: "m".into(),
            },
            VaultError::Other("o".into()),
        ];

        for err in &errors {
            let _ = format!("{err}");
            let _ = format!("{err:?}");
        }
    }
}

// ---------------------------------------------------------------------------
// VaultKeeper setup/authorize integration tests
// ---------------------------------------------------------------------------

mod vault_keeper {
    use super::*;
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    /// A test host that provides config from memory.
    struct TestHost {
        files: Mutex<HashMap<PathBuf, Vec<u8>>>,
        config_dir: PathBuf,
    }

    impl TestHost {
        fn with_config() -> Self {
            let config_dir = PathBuf::from("/test/config");
            let config_json = serde_json::to_string_pretty(&serde_json::json!({
                "version": 1,
                "backends": [{ "type": "file", "enabled": true }],
                "keyRotation": { "gracePeriodDays": 7 },
                "defaults": { "ttlMinutes": 60, "trustTier": "3" }
            }))
            .unwrap()
                + "\n";

            let mut files = HashMap::new();
            files.insert(config_dir.join("config.json"), config_json.into_bytes());

            Self {
                files: Mutex::new(files),
                config_dir,
            }
        }
    }

    #[async_trait::async_trait]
    impl HostPlatform for TestHost {
        async fn exec(
            &self,
            _cmd: &str,
            _args: &[&str],
            _stdin: Option<&[u8]>,
        ) -> Result<ExecOutput, VaultError> {
            // Return "openssl OK" so doctor checks pass
            Ok(ExecOutput {
                stdout: b"OpenSSL 3.0.0 1 Jan 2024".to_vec(),
                stderr: Vec::new(),
                exit_code: 0,
            })
        }
        async fn read_file(&self, path: &Path) -> Result<Vec<u8>, VaultError> {
            self.files
                .lock()
                .unwrap()
                .get(path)
                .cloned()
                .ok_or_else(|| VaultError::Other(format!("Not found: {}", path.display())))
        }
        async fn write_file(
            &self,
            path: &Path,
            content: &[u8],
            _mode: u32,
        ) -> Result<(), VaultError> {
            self.files
                .lock()
                .unwrap()
                .insert(path.to_path_buf(), content.to_vec());
            Ok(())
        }
        async fn file_exists(&self, path: &Path) -> Result<bool, VaultError> {
            Ok(self.files.lock().unwrap().contains_key(path))
        }
        async fn delete_file(&self, path: &Path) -> Result<(), VaultError> {
            self.files
                .lock()
                .unwrap()
                .remove(path)
                .ok_or_else(|| VaultError::Other(format!("Not found: {}", path.display())))?;
            Ok(())
        }
        async fn list_dir(&self, path: &Path) -> Result<Vec<String>, VaultError> {
            let files = self.files.lock().unwrap();
            Ok(files
                .keys()
                .filter_map(|k| {
                    if k.parent() == Some(path) {
                        k.file_name().and_then(|n| n.to_str()).map(String::from)
                    } else {
                        None
                    }
                })
                .collect())
        }
        fn platform(&self) -> Platform {
            Platform::Linux
        }
        fn config_dir(&self) -> &Path {
            &self.config_dir
        }
    }

    #[tokio::test]
    async fn init_with_config_succeeds() {
        let host = TestHost::with_config();
        let vault = VaultKeeper::init(
            &host,
            Some(VaultKeeperOptions {
                skip_doctor: true,
                ..Default::default()
            }),
        )
        .await
        .unwrap();

        assert_eq!(vault.config().version, 1);
        assert_eq!(vault.config().defaults.ttl_minutes, 60);
    }

    #[tokio::test]
    async fn setup_produces_jwe_token() {
        let host = TestHost::with_config();
        let vault = VaultKeeper::init(
            &host,
            Some(VaultKeeperOptions {
                skip_doctor: true,
                ..Default::default()
            }),
        )
        .await
        .unwrap();

        let token = vault
            .setup(
                "my-secret",
                "s3cret-value",
                Some(&vaultkeeper_core::vault::SetupOptions {
                    skip_trust: Some(true),
                    ..Default::default()
                }),
            )
            .unwrap();

        // JWE compact serialization has 5 dot-separated parts
        assert_eq!(token.split('.').count(), 5);
    }

    // --- Explicit executable-trust contract (parity with #123/#131) ---

    async fn dev_vault() -> VaultKeeper {
        let host = TestHost::with_config();
        VaultKeeper::init(
            &host,
            Some(VaultKeeperOptions {
                skip_doctor: true,
                ..Default::default()
            }),
        )
        .await
        .unwrap()
    }

    /// #147: setup() with no options must not silently mint an unverified token —
    /// it requires an explicit executable-trust choice (missing-choice).
    #[tokio::test]
    async fn setup_without_options_rejects_missing_choice() {
        let vault = dev_vault().await;
        let err = vault.setup("s", "v", None).unwrap_err();
        match err {
            VaultError::ExecutableTrustRequired { reason, .. } => {
                assert_eq!(reason, ExecutableTrustRequiredReason::MissingChoice);
            }
            other => panic!("expected ExecutableTrustRequired, got {other:?}"),
        }
    }

    /// #147: empty options (neither executable_path nor skip_trust) is also a
    /// missing choice, not a silent default to "dev".
    #[tokio::test]
    async fn setup_with_empty_options_rejects_missing_choice() {
        let vault = dev_vault().await;
        let opts = vaultkeeper_core::vault::SetupOptions::default();
        let err = vault.setup("s", "v", Some(&opts)).unwrap_err();
        match err {
            VaultError::ExecutableTrustRequired { reason, .. } => {
                assert_eq!(reason, ExecutableTrustRequiredReason::MissingChoice);
            }
            other => panic!("expected ExecutableTrustRequired, got {other:?}"),
        }
    }

    /// #147: supplying both executable_path and skip_trust is a conflicting
    /// (mutually exclusive) choice.
    #[tokio::test]
    async fn setup_with_conflicting_choice_rejects() {
        let vault = dev_vault().await;
        let opts = vaultkeeper_core::vault::SetupOptions {
            executable_path: Some("/usr/bin/node".to_string()),
            skip_trust: Some(true),
            ..Default::default()
        };
        let err = vault.setup("s", "v", Some(&opts)).unwrap_err();
        match err {
            VaultError::ExecutableTrustRequired { reason, .. } => {
                assert_eq!(reason, ExecutableTrustRequiredReason::ConflictingChoice);
            }
            other => panic!("expected ExecutableTrustRequired, got {other:?}"),
        }
    }

    /// #147: the retired legacy `"dev"` sentinel as executable_path is rejected,
    /// pointing migrating callers at skip_trust.
    #[tokio::test]
    async fn setup_with_legacy_dev_sentinel_rejects() {
        let vault = dev_vault().await;
        let opts = vaultkeeper_core::vault::SetupOptions {
            executable_path: Some("dev".to_string()),
            ..Default::default()
        };
        let err = vault.setup("s", "v", Some(&opts)).unwrap_err();
        match err {
            VaultError::ExecutableTrustRequired { reason, .. } => {
                assert_eq!(reason, ExecutableTrustRequiredReason::LegacyDevSentinel);
            }
            other => panic!("expected ExecutableTrustRequired, got {other:?}"),
        }
    }

    /// #147: the explicit development-only opt-out mints a token bound to the
    /// "dev" sentinel identity.
    #[tokio::test]
    async fn setup_with_skip_trust_binds_dev_identity() {
        let mut vault = dev_vault().await;
        let opts = vaultkeeper_core::vault::SetupOptions {
            skip_trust: Some(true),
            ..Default::default()
        };
        let token = vault.setup("s", "v", Some(&opts)).unwrap();
        let (claims, _) = vault.authorize(&token).unwrap();
        assert_eq!(claims.exe, "dev");
    }

    /// #147: an explicit executable_path binds that path into the token.
    #[tokio::test]
    async fn setup_with_executable_path_binds_it() {
        let mut vault = dev_vault().await;
        let opts = vaultkeeper_core::vault::SetupOptions {
            executable_path: Some("/usr/bin/node".to_string()),
            ..Default::default()
        };
        let token = vault.setup("s", "v", Some(&opts)).unwrap();
        let (claims, _) = vault.authorize(&token).unwrap();
        assert_eq!(claims.exe, "/usr/bin/node");
    }

    /// #147 (review): an empty or whitespace-only executable_path is not a valid
    /// trust choice — it must be rejected up front, not minted into a token
    /// whose empty `exe` claim authorize() would later reject as unusable.
    #[tokio::test]
    async fn setup_with_empty_executable_path_rejects_missing_choice() {
        for bad in ["", "   ", "\t"] {
            let vault = dev_vault().await;
            let opts = vaultkeeper_core::vault::SetupOptions {
                executable_path: Some(bad.to_string()),
                ..Default::default()
            };
            let err = vault.setup("s", "v", Some(&opts)).unwrap_err();
            match err {
                VaultError::ExecutableTrustRequired { reason, .. } => {
                    assert_eq!(
                        reason,
                        ExecutableTrustRequiredReason::MissingChoice,
                        "input {bad:?}"
                    );
                }
                other => panic!("expected ExecutableTrustRequired for {bad:?}, got {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn setup_authorize_round_trip() {
        let host = TestHost::with_config();
        let mut vault = VaultKeeper::init(
            &host,
            Some(VaultKeeperOptions {
                skip_doctor: true,
                ..Default::default()
            }),
        )
        .await
        .unwrap();

        let token = vault
            .setup(
                "db-password",
                "hunter2",
                Some(&vaultkeeper_core::vault::SetupOptions {
                    skip_trust: Some(true),
                    ..Default::default()
                }),
            )
            .unwrap();
        let (claims, response) = vault.authorize(&token).unwrap();

        assert_eq!(claims.sub, "db-password");
        assert_eq!(claims.val, "hunter2");
        assert_eq!(claims.reference, "db-password");
        assert_eq!(claims.tid, TrustTier::Dev);
        assert_eq!(response.key_status, KeyStatus::Current);
        assert!(response.rotated_jwt.is_none());
    }

    #[tokio::test]
    async fn authorize_with_rotated_key_re_encrypts() {
        let host = TestHost::with_config();
        let mut vault = VaultKeeper::init(
            &host,
            Some(VaultKeeperOptions {
                skip_doctor: true,
                ..Default::default()
            }),
        )
        .await
        .unwrap();

        // Create token with initial key
        let token = vault
            .setup(
                "api-key",
                "abc123",
                Some(&vaultkeeper_core::vault::SetupOptions {
                    skip_trust: Some(true),
                    ..Default::default()
                }),
            )
            .unwrap();

        // Rotate the key
        vault.rotate_key().unwrap();

        // Authorize should succeed (finds previous key) and provide a rotated JWT
        let (claims, response) = vault.authorize(&token).unwrap();
        assert_eq!(claims.val, "abc123");
        assert_eq!(response.key_status, KeyStatus::Previous);
        assert!(response.rotated_jwt.is_some());

        // The rotated JWT should decrypt with the current key
        let (claims2, response2) = vault
            .authorize(response.rotated_jwt.as_ref().unwrap())
            .unwrap();
        assert_eq!(claims2.val, "abc123");
        assert_eq!(response2.key_status, KeyStatus::Current);
        assert!(response2.rotated_jwt.is_none());
    }

    #[tokio::test]
    async fn authorize_rejects_token_from_revoked_key() {
        let host = TestHost::with_config();
        let mut vault = VaultKeeper::init(
            &host,
            Some(VaultKeeperOptions {
                skip_doctor: true,
                ..Default::default()
            }),
        )
        .await
        .unwrap();

        let token = vault
            .setup(
                "key",
                "val",
                Some(&vaultkeeper_core::vault::SetupOptions {
                    skip_trust: Some(true),
                    ..Default::default()
                }),
            )
            .unwrap();

        // Revoke all keys — generates a completely new key
        vault.revoke_key().unwrap();

        // Token should fail to authorize (unknown key)
        let result = vault.authorize(&token);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn setup_with_custom_ttl() {
        let host = TestHost::with_config();
        let mut vault = VaultKeeper::init(
            &host,
            Some(VaultKeeperOptions {
                skip_doctor: true,
                ..Default::default()
            }),
        )
        .await
        .unwrap();

        let opts = vaultkeeper_core::vault::SetupOptions {
            ttl_minutes: Some(5),
            skip_trust: Some(true),
            ..Default::default()
        };
        let token = vault.setup("key", "val", Some(&opts)).unwrap();
        let (claims, _) = vault.authorize(&token).unwrap();

        // Token should expire in ~5 minutes
        let expected_ttl = 5 * 60;
        let actual_ttl = claims.exp - claims.iat;
        assert_eq!(actual_ttl, expected_ttl);
    }

    #[tokio::test]
    async fn init_with_doctor_scopes_to_backends() {
        // TestHost returns "openssl OK" for all exec calls and platform is Linux.
        // With file-only backends, secret-tool is demoted, so init should succeed
        // even though secret-tool is "missing" (all exec calls return openssl output,
        // which passes the openssl check but not secret-tool; however, since file
        // backend doesn't require secret-tool, it's demoted to optional).
        let host = TestHost::with_config();
        let result = VaultKeeper::init(
            &host,
            Some(VaultKeeperOptions {
                skip_doctor: false, // exercise the doctor path
                ..Default::default()
            }),
        )
        .await;

        // The exec mock returns generic openssl output for every command,
        // which makes openssl pass. bash will also "pass" because exit_code=0.
        // secret-tool check may report "missing" but since file backend is the
        // only enabled backend, it is demoted to optional, so init succeeds.
        assert!(
            result.is_ok(),
            "init with file-only backend should succeed even if secret-tool would fail"
        );
    }

    #[tokio::test]
    async fn authorize_enforces_use_limit() {
        let host = TestHost::with_config();
        let mut vault = VaultKeeper::init(
            &host,
            Some(VaultKeeperOptions {
                skip_doctor: true,
                ..Default::default()
            }),
        )
        .await
        .unwrap();

        let opts = vaultkeeper_core::vault::SetupOptions {
            use_limit: Some(2),
            skip_trust: Some(true),
            ..Default::default()
        };
        let token = vault.setup("limited", "val", Some(&opts)).unwrap();

        // First two authorizations succeed
        let (claims, _) = vault.authorize(&token).unwrap();
        assert_eq!(claims.val, "val");
        let (claims2, _) = vault.authorize(&token).unwrap();
        assert_eq!(claims2.val, "val");

        // Third should fail — usage limit exceeded
        let result = vault.authorize(&token);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, VaultError::UsageLimitExceeded { .. })
                || matches!(err, VaultError::TokenRevoked { .. }),
            "Expected UsageLimitExceeded or TokenRevoked, got: {err}"
        );
    }
}

// ---------------------------------------------------------------------------
// Doctor backend-aware scoping tests
// ---------------------------------------------------------------------------

mod doctor_scoping {
    use super::*;
    use std::path::Path;

    /// A test host that returns a fixed platform and generic "ok" exec output.
    /// All check functions will see exit_code=0 and openssl-like stdout, which
    /// means they will either pass or be classified based on their version
    /// parsing logic (some checks look for specific version strings).
    struct DoctorTestHost {
        plat: Platform,
    }

    #[async_trait::async_trait]
    impl HostPlatform for DoctorTestHost {
        async fn exec(
            &self,
            _cmd: &str,
            _args: &[&str],
            _stdin: Option<&[u8]>,
        ) -> Result<ExecOutput, VaultError> {
            // Return a generic successful output that passes most checks.
            Ok(ExecOutput {
                stdout: b"OpenSSL 3.0.0 1 Jan 2024\nGNU bash, version 5.2\n".to_vec(),
                stderr: Vec::new(),
                exit_code: 0,
            })
        }
        async fn read_file(&self, _path: &Path) -> Result<Vec<u8>, VaultError> {
            Err(VaultError::Other("not found".into()))
        }
        async fn write_file(
            &self,
            _path: &Path,
            _content: &[u8],
            _mode: u32,
        ) -> Result<(), VaultError> {
            Ok(())
        }
        async fn file_exists(&self, _path: &Path) -> Result<bool, VaultError> {
            Ok(false)
        }
        async fn delete_file(&self, _path: &Path) -> Result<(), VaultError> {
            Ok(())
        }
        async fn list_dir(&self, _path: &Path) -> Result<Vec<String>, VaultError> {
            Ok(Vec::new())
        }
        fn platform(&self) -> Platform {
            self.plat
        }
        fn config_dir(&self) -> &Path {
            Path::new("/test/config")
        }
    }

    #[tokio::test]
    async fn none_backends_uses_platform_defaults() {
        let host = DoctorTestHost {
            plat: Platform::Linux,
        };
        let result = vaultkeeper_core::doctor::run_doctor(&host, None).await;

        // With None, all platform-default checks are required (backward compat).
        // The generic exec output passes openssl and bash, but secret-tool's
        // version parsing may or may not pass. Regardless, all checks should run.
        assert!(result.checks.len() >= 4); // openssl, bash, secret-tool, op, ykman
    }

    #[tokio::test]
    async fn file_only_backend_on_linux_demotes_secret_tool() {
        let host = DoctorTestHost {
            plat: Platform::Linux,
        };
        let backends = vec![BackendConfig {
            backend_type: "file".to_string(),
            enabled: true,
            plugin: None,
            path: None,
            options: None,
        }];
        let result = vaultkeeper_core::doctor::run_doctor(&host, Some(&backends)).await;

        // With file-only backend, secret-tool is demoted to optional.
        // Even if secret-tool check reports non-ok, ready should still be true
        // because it's not required.
        // (openssl and bash should pass with our mock output)
        assert!(
            result.ready,
            "file-only backend should not block on secret-tool: next_steps={:?}",
            result.next_steps
        );
    }

    // Issue #116: `checks[].required` must reflect scoping so the CLI can
    // avoid rendering a failing icon for plugin-backend checks (op/ykman)
    // that aren't configured — the file backend needs neither.
    #[tokio::test]
    async fn file_only_backend_marks_op_and_ykman_as_not_required() {
        let host = DoctorTestHost {
            plat: Platform::Linux,
        };
        let backends = vec![BackendConfig {
            backend_type: "file".to_string(),
            enabled: true,
            plugin: None,
            path: None,
            options: None,
        }];
        let result = vaultkeeper_core::doctor::run_doctor(&host, Some(&backends)).await;

        let op = result
            .checks
            .iter()
            .find(|c| c.check.name == "op")
            .expect("op check present");
        let ykman = result
            .checks
            .iter()
            .find(|c| c.check.name == "ykman")
            .expect("ykman check present");
        assert!(!op.required, "op should not be required for file backend");
        assert!(
            !ykman.required,
            "ykman should not be required for file backend"
        );
    }

    // Issue #116, acceptance criterion 3: the yubikey backend promotes
    // ykman back to required.
    #[tokio::test]
    async fn yubikey_backend_marks_ykman_as_required() {
        let host = DoctorTestHost {
            plat: Platform::Linux,
        };
        let backends = vec![BackendConfig {
            backend_type: "yubikey".to_string(),
            enabled: true,
            plugin: Some(true),
            path: None,
            options: None,
        }];
        let result = vaultkeeper_core::doctor::run_doctor(&host, Some(&backends)).await;

        let ykman = result
            .checks
            .iter()
            .find(|c| c.check.name == "ykman")
            .expect("ykman check present");
        assert!(
            ykman.required,
            "ykman should be required when yubikey backend is enabled"
        );
    }

    #[tokio::test]
    async fn disabled_backend_does_not_require_its_tool() {
        let host = DoctorTestHost {
            plat: Platform::Linux,
        };
        let backends = vec![
            BackendConfig {
                backend_type: "file".to_string(),
                enabled: true,
                plugin: None,
                path: None,
                options: None,
            },
            BackendConfig {
                backend_type: "secret-tool".to_string(),
                enabled: false,
                plugin: None,
                path: None,
                options: None,
            },
        ];
        let result = vaultkeeper_core::doctor::run_doctor(&host, Some(&backends)).await;

        // Disabled secret-tool backend should not make secret-tool required
        assert!(
            result.ready,
            "disabled secret-tool backend should not block readiness: next_steps={:?}",
            result.next_steps
        );
    }

    #[tokio::test]
    async fn empty_backends_demotes_all_platform_checks() {
        let host = DoctorTestHost {
            plat: Platform::Linux,
        };
        let backends: Vec<BackendConfig> = vec![];
        let result = vaultkeeper_core::doctor::run_doctor(&host, Some(&backends)).await;

        // Empty backends = no backend needs any platform tool.
        // Only core checks (openssl) remain required.
        assert!(
            result.ready,
            "empty backends should demote all platform checks: next_steps={:?}",
            result.next_steps
        );
    }
}
