//! Comprehensive unit tests for vaultkeeper-core.
//!
//! @see RFC 7516 (JWE Compact Serialization)
//! @see RFC 5116 (AES-GCM)

use vaultkeeper_core::backend::{BackendRegistry, ExecOptions, ExecOutput, HostPlatform, Platform};
use vaultkeeper_core::config::{
    default_backend_type_for_platform, default_config, load_config_from_str, validate_config,
};
use vaultkeeper_core::errors::{ExecutableTrustRequiredReason, VaultError};
use vaultkeeper_core::keys::KeyManager;
use vaultkeeper_core::types::{
    BackendConfig, DevelopmentMode, KeyRotationPolicy, KeyStatus, SecretAccessor, TrustTier,
    VaultClaims, VaultConfig, VaultDefaults, VaultResponse,
};
use vaultkeeper_core::vault::VaultKeeperOptions;
use vaultkeeper_core::{InMemoryBackend, VaultKeeper};
use zeroize::Zeroizing;

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
    fn default_config_is_file_backend_on_every_platform() {
        // Regression test for #98 / #235: the zero-config default must
        // resolve to the 'file' backend on macOS, Windows, and Linux — never
        // a platform-native keychain/dpapi store, which would silently
        // reintroduce the #98 regression once the wasm core swap lands.
        //
        // Parameterized over the `Platform` enum (rather than
        // `#[cfg(target_os = ...)]`) so all three arms are exercised
        // regardless of which OS actually runs this test.
        for platform in [Platform::Darwin, Platform::Linux, Platform::Windows] {
            assert_eq!(
                default_backend_type_for_platform(platform),
                "file",
                "platform {platform:?} must default to the 'file' backend (#98)"
            );
        }

        let cfg = default_config();
        assert_eq!(cfg.backends[0].backend_type, "file");
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

    // Regression for issue #200: `config init` (TS CLI + README) writes
    // `"trustTier": 3` as a bare JSON number. Before the fix the Rust-core
    // reader required a string-encoded number, so the WASM SDK could not read a
    // CLI-produced config. The reader must accept the numeric form.
    #[test]
    fn load_config_accepts_numeric_trust_tier() {
        let json = r#"{
            "version": 1,
            "backends": [{"type": "file", "enabled": true}],
            "keyRotation": {"gracePeriodDays": 7},
            "defaults": {"ttlMinutes": 60, "trustTier": 3}
        }"#;
        let cfg = load_config_from_str(json).unwrap();
        assert_eq!(cfg.defaults.trust_tier, TrustTier::Dev);
    }

    // Backward compatibility: string-encoded trust tiers (older native-CLI
    // output) must still load after the leniency change in issue #200.
    #[test]
    fn load_config_still_accepts_string_trust_tier() {
        let json = r#"{
            "version": 1,
            "backends": [{"type": "file", "enabled": true}],
            "keyRotation": {"gracePeriodDays": 7},
            "defaults": {"ttlMinutes": 60, "trustTier": "1"}
        }"#;
        let cfg = load_config_from_str(json).unwrap();
        assert_eq!(cfg.defaults.trust_tier, TrustTier::Sigstore);
    }

    #[test]
    fn load_config_rejects_out_of_range_trust_tier() {
        let json = r#"{
            "version": 1,
            "backends": [{"type": "file", "enabled": true}],
            "keyRotation": {"gracePeriodDays": 7},
            "defaults": {"ttlMinutes": 60, "trustTier": 4}
        }"#;
        assert!(load_config_from_str(json).is_err());
    }

    // The canonical config wire form is a bare number, matching the TS CLI,
    // the TS library, and the README example (issue #200). The native CLI
    // serializes `default_config()`, so this guards the writer side too.
    #[test]
    fn default_config_serializes_trust_tier_as_number() {
        let json = serde_json::to_string(&default_config()).unwrap();
        assert!(
            json.contains("\"trustTier\":3"),
            "expected bare-number trustTier in {json}"
        );
        assert!(
            !json.contains("\"trustTier\":\"3\""),
            "config trustTier must not be a string: {json}"
        );
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
                code: None,
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

        /// Seed an in-memory file (e.g. a fake executable to hash for trust
        /// verification).
        fn add_file(&self, path: &str, content: &[u8]) {
            self.files
                .lock()
                .unwrap()
                .insert(PathBuf::from(path), content.to_vec());
        }
    }

    #[async_trait::async_trait]
    impl HostPlatform for TestHost {
        async fn exec(
            &self,
            _cmd: &str,
            _args: &[&str],
            _options: ExecOptions<'_>,
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
                &host,
                "my-secret",
                "s3cret-value",
                Some(&vaultkeeper_core::vault::SetupOptions {
                    skip_trust: Some(true),
                    ..Default::default()
                }),
            )
            .await
            .unwrap();

        // JWE compact serialization has 5 dot-separated parts
        assert_eq!(token.split('.').count(), 5);
    }

    // --- Explicit executable-trust contract (parity with #123/#131) ---

    async fn dev_vault() -> (TestHost, VaultKeeper) {
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
        (host, vault)
    }

    /// Load the on-disk trust manifest for a `TestHost` as a JSON value, or
    /// `None` when no manifest has been written. Lets trust tests assert on the
    /// manifest without depending on core-internal manifest types.
    fn read_trust_manifest(host: &TestHost) -> Option<serde_json::Value> {
        let path = host.config_dir().join("trust-manifest.json");
        let bytes = host.files.lock().unwrap().get(&path).cloned()?;
        Some(serde_json::from_slice(&bytes).expect("trust manifest is valid JSON"))
    }

    /// True when `hash` appears among the approved hashes for `namespace` in the
    /// written trust manifest.
    fn manifest_has_hash(host: &TestHost, namespace: &str, hash: &str) -> bool {
        let Some(manifest) = read_trust_manifest(host) else {
            return false;
        };
        manifest
            .get("entries")
            .and_then(|e| e.get(namespace))
            .and_then(|entry| entry.get("hashes"))
            .and_then(|h| h.as_array())
            .is_some_and(|hashes| hashes.iter().any(|h| h.as_str() == Some(hash)))
    }

    // SHA-256 hex digests of the fake executable bytes used by the trust tests,
    // computed independently (`printf '<bytes>' | shasum -a 256`) so assertions
    // are spec-derived, not read back from the implementation.
    // @see RFC 6234 (SHA-256)
    const HASH_APP_BINARY_BYTES: &str =
        "b6bfaadaaa3dc2d0024335b614af5360df7492b3f28dd7d5bb8c17019624cfc7";
    const HASH_ORIGINAL_BYTES: &str =
        "8e338be649868e7c9e053212037e4bb0965ba7653e81b974bab76578bd59c80a";
    const HASH_TAMPERED_BYTES: &str =
        "dd7046110708421cd0c00f2c1ebcb4e5b4c3790cbd821377e3b9bf0274f7c0ed";

    /// #147: setup() with no options must not silently mint an unverified token —
    /// it requires an explicit executable-trust choice (missing-choice).
    #[tokio::test]
    async fn setup_without_options_rejects_missing_choice() {
        let (host, vault) = dev_vault().await;
        let err = vault.setup(&host, "s", "v", None).await.unwrap_err();
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
        let (host, vault) = dev_vault().await;
        let opts = vaultkeeper_core::vault::SetupOptions::default();
        let err = vault.setup(&host, "s", "v", Some(&opts)).await.unwrap_err();
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
        let (host, vault) = dev_vault().await;
        let opts = vaultkeeper_core::vault::SetupOptions {
            executable_path: Some("/usr/bin/node".to_string()),
            skip_trust: Some(true),
            ..Default::default()
        };
        let err = vault.setup(&host, "s", "v", Some(&opts)).await.unwrap_err();
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
        let (host, vault) = dev_vault().await;
        let opts = vaultkeeper_core::vault::SetupOptions {
            executable_path: Some("dev".to_string()),
            ..Default::default()
        };
        let err = vault.setup(&host, "s", "v", Some(&opts)).await.unwrap_err();
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
        let (host, mut vault) = dev_vault().await;
        let opts = vaultkeeper_core::vault::SetupOptions {
            skip_trust: Some(true),
            ..Default::default()
        };
        let token = vault.setup(&host, "s", "v", Some(&opts)).await.unwrap();
        let (_handle, claims, _) = vault.authorize(&token).unwrap();
        assert_eq!(claims.exe, "dev");
    }

    /// #166: an explicit executable_path is verified (hashed + TOFU-recorded) and
    /// the *verified hash* — not the raw path — is bound into the token's `exe`
    /// claim. A first encounter records the hash in the trust manifest.
    #[tokio::test]
    async fn setup_with_executable_path_verifies_and_records_hash() {
        let (host, mut vault) = dev_vault().await;
        host.add_file("/usr/bin/app", b"app-binary-bytes");

        let opts = vaultkeeper_core::vault::SetupOptions {
            executable_path: Some("/usr/bin/app".to_string()),
            ..Default::default()
        };
        let token = vault.setup(&host, "s", "v", Some(&opts)).await.unwrap();
        let (_handle, claims, _) = vault.authorize(&token).unwrap();

        // exe claim holds the verified hash (mirrors the TS library), not the path.
        assert_eq!(claims.exe, HASH_APP_BINARY_BYTES);
        // First encounter recorded the hash under the executable's namespace.
        assert!(manifest_has_hash(
            &host,
            "/usr/bin/app",
            HASH_APP_BINARY_BYTES
        ));
    }

    /// #166: a second setup for the same unchanged executable matches the
    /// recorded hash (registry tier) and succeeds, binding the same hash.
    #[tokio::test]
    async fn setup_with_executable_path_matching_hash_passes() {
        let (host, mut vault) = dev_vault().await;
        host.add_file("/usr/bin/app", b"app-binary-bytes");
        let opts = vaultkeeper_core::vault::SetupOptions {
            executable_path: Some("/usr/bin/app".to_string()),
            ..Default::default()
        };

        // First encounter records the hash.
        vault.setup(&host, "s", "v", Some(&opts)).await.unwrap();
        // Second setup finds the matching hash and still binds it.
        let token = vault.setup(&host, "s", "v", Some(&opts)).await.unwrap();
        let (_handle, claims, _) = vault.authorize(&token).unwrap();
        assert_eq!(claims.exe, HASH_APP_BINARY_BYTES);
    }

    /// #166 / #148: when the executable's hash changes from a previously approved
    /// value, setup() fails with IdentityMismatch and the conflicting (new) hash
    /// is never written to the manifest — the failed setup leaves it unchanged.
    #[tokio::test]
    async fn setup_with_executable_path_conflicting_hash_errors_and_records_nothing() {
        let (host, vault) = dev_vault().await;
        host.add_file("/usr/bin/app", b"original-bytes");
        let opts = vaultkeeper_core::vault::SetupOptions {
            executable_path: Some("/usr/bin/app".to_string()),
            ..Default::default()
        };

        // First encounter records the original hash.
        vault.setup(&host, "s", "v", Some(&opts)).await.unwrap();

        // Tamper with the executable so its hash changes.
        host.add_file("/usr/bin/app", b"tampered-bytes");
        let err = vault.setup(&host, "s", "v", Some(&opts)).await.unwrap_err();
        match err {
            VaultError::IdentityMismatch {
                previous_hash,
                current_hash,
                ..
            } => {
                assert_eq!(previous_hash, HASH_ORIGINAL_BYTES);
                assert_eq!(current_hash, HASH_TAMPERED_BYTES);
            }
            other => panic!("expected IdentityMismatch, got {other:?}"),
        }

        // The failed setup wrote nothing new: only the original hash remains.
        assert!(manifest_has_hash(
            &host,
            "/usr/bin/app",
            HASH_ORIGINAL_BYTES
        ));
        assert!(!manifest_has_hash(
            &host,
            "/usr/bin/app",
            HASH_TAMPERED_BYTES
        ));
    }

    /// #166 / #148: a setup that fails during verification (the executable
    /// cannot be read/hashed) leaves the trust manifest entirely unwritten.
    #[tokio::test]
    async fn setup_with_unreadable_executable_leaves_manifest_unwritten() {
        let (host, vault) = dev_vault().await;
        // Note: no file seeded at this path, so hashing fails.
        let opts = vaultkeeper_core::vault::SetupOptions {
            executable_path: Some("/usr/bin/missing".to_string()),
            ..Default::default()
        };
        let err = vault.setup(&host, "s", "v", Some(&opts)).await.unwrap_err();
        // Verification failed before any token minted; nothing was recorded.
        assert!(!matches!(err, VaultError::ExecutableTrustRequired { .. }));
        assert!(read_trust_manifest(&host).is_none());
    }

    /// #147 (review): an empty or whitespace-only executable_path is not a valid
    /// trust choice — it must be rejected up front, not hashed or minted into a
    /// token whose empty `exe` claim authorize() would later reject as unusable.
    #[tokio::test]
    async fn setup_with_empty_executable_path_rejects_missing_choice() {
        for bad in ["", "   ", "\t"] {
            let (host, vault) = dev_vault().await;
            let opts = vaultkeeper_core::vault::SetupOptions {
                executable_path: Some(bad.to_string()),
                ..Default::default()
            };
            let err = vault.setup(&host, "s", "v", Some(&opts)).await.unwrap_err();
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
                &host,
                "db-password",
                "hunter2",
                Some(&vaultkeeper_core::vault::SetupOptions {
                    skip_trust: Some(true),
                    ..Default::default()
                }),
            )
            .await
            .unwrap();
        let (handle, claims, response) = vault.authorize(&token).unwrap();

        assert_eq!(claims.sub, "db-password");
        // issue #241 AC1: authorize() never returns the raw secret.
        assert_eq!(claims.val, "");
        assert_eq!(claims.reference, "db-password");
        assert_eq!(claims.tid, TrustTier::Dev);
        assert_eq!(response.key_status, KeyStatus::Current);
        assert!(response.rotated_jwt.is_none());

        // The secret is readable exactly once, via the handle.
        let secret = vault.read_secret(&handle).unwrap();
        assert_eq!(secret.as_str(), "hunter2");
        let err = vault.read_secret(&handle).unwrap_err();
        assert!(matches!(err, VaultError::AccessorConsumed { .. }));
    }

    /// Regression test: `authorize()` used to build its returned (redacted)
    /// claims by cloning the *full* `VaultClaims` — secret `val` included —
    /// into a second `String` allocation, then `std::mem::take`-ing that
    /// clone's `val` back out and dropping it. A plain `String`'s `Drop`
    /// does not zero its buffer before freeing, so that dropped clone left
    /// the plaintext secret sitting in freed heap memory — never zeroized,
    /// contradicting the "Zero `Buffer` instances containing secrets after
    /// use" rule. The fix builds the redacted `VaultClaims` field-by-field,
    /// never touching (let alone cloning) `val`, so `claims.val`'s only
    /// value ever assigned is `String::new()` and the *sole* copy of the
    /// secret bytes moves straight from the decrypted claims into the
    /// handle table's `Zeroizing<String>` buffer via `insert_secret`.
    ///
    /// **What this test can and cannot prove:** it structurally asserts
    /// (a) the returned claims never carry the secret in `val` or anywhere
    /// else observable, and (b) the only way to recover the secret is
    /// through `read_secret`, which returns a `Zeroizing<String>` (a type
    /// that zeroes its buffer on drop — enforced by the `zeroize` crate, not
    /// re-derived here). It cannot directly observe heap contents to prove
    /// no *unprotected* copy was ever created and dropped along the way —
    /// that would need unsafe memory inspection or a custom allocator
    /// harness, which is out of scope here. The regression this guards
    /// against is a *source-level* one (a `clone()` that pulls the secret
    /// into a second, non-zeroizing buffer before scrubbing it) — reading
    /// this test alongside `authorize()`'s implementation is what actually
    /// closes the loop: there is no `claims.clone()` left in that function
    /// to reintroduce the bug.
    #[tokio::test]
    async fn authorize_never_clones_the_secret_into_public_claims() {
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
                &host,
                "db-password",
                "hunter2-clone-regression",
                Some(&vaultkeeper_core::vault::SetupOptions {
                    skip_trust: Some(true),
                    ..Default::default()
                }),
            )
            .await
            .unwrap();

        let (handle, claims, _response) = vault.authorize(&token).unwrap();
        assert_eq!(
            claims.val, "",
            "returned claims must never carry the secret"
        );
        // The claims struct's Debug output is the most likely accidental
        // leak path (a log statement, a test failure message) — assert the
        // secret does not appear there either.
        assert!(!format!("{claims:?}").contains("hunter2-clone-regression"));

        // The secret is recoverable exactly once, and only through the
        // Zeroizing-typed one-time accessor.
        let secret: Zeroizing<String> = vault.read_secret(&handle).unwrap();
        assert_eq!(secret.as_str(), "hunter2-clone-regression");
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
                &host,
                "api-key",
                "abc123",
                Some(&vaultkeeper_core::vault::SetupOptions {
                    skip_trust: Some(true),
                    ..Default::default()
                }),
            )
            .await
            .unwrap();

        // Rotate the key
        vault.rotate_key(&host).await.unwrap();

        // Authorize should succeed (finds previous key) and provide a rotated JWT
        let (handle, claims, response) = vault.authorize(&token).unwrap();
        assert_eq!(claims.val, "");
        assert_eq!(vault.read_secret(&handle).unwrap().as_str(), "abc123");
        assert_eq!(response.key_status, KeyStatus::Previous);
        assert!(response.rotated_jwt.is_some());

        // The rotated JWT should decrypt with the current key
        let (handle2, claims2, response2) = vault
            .authorize(response.rotated_jwt.as_ref().unwrap())
            .unwrap();
        assert_eq!(claims2.val, "");
        assert_eq!(vault.read_secret(&handle2).unwrap().as_str(), "abc123");
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
                &host,
                "key",
                "val",
                Some(&vaultkeeper_core::vault::SetupOptions {
                    skip_trust: Some(true),
                    ..Default::default()
                }),
            )
            .await
            .unwrap();

        // Revoke all keys — generates a completely new key
        vault.revoke_key(&host).await.unwrap();

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
        let token = vault.setup(&host, "key", "val", Some(&opts)).await.unwrap();
        let (_handle, claims, _) = vault.authorize(&token).unwrap();

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
        let token = vault
            .setup(&host, "limited", "val", Some(&opts))
            .await
            .unwrap();

        // First two authorizations succeed
        let (handle, claims, _) = vault.authorize(&token).unwrap();
        assert_eq!(claims.val, "");
        assert_eq!(vault.read_secret(&handle).unwrap().as_str(), "val");
        let (handle2, claims2, _) = vault.authorize(&token).unwrap();
        assert_eq!(claims2.val, "");
        assert_eq!(vault.read_secret(&handle2).unwrap().as_str(), "val");

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

    /// Regression test for the documented invariant that use-limit
    /// exhaustion governs the *token's* ability to mint new handles, not the
    /// liveness of handles already minted: a handle returned by an earlier,
    /// successful `authorize()` call must keep resolving and reading its
    /// secret even after the token itself has been refused for exceeding its
    /// `use_limit`. Exhaustion blocks *future* `authorize()` calls on the
    /// token (no new handles are minted); it neither evicts nor otherwise
    /// invalidates a handle already handed out — see the eviction-policy
    /// section of `crates/vaultkeeper-core/src/identity/handles.rs`.
    #[tokio::test]
    async fn handles_already_minted_survive_use_limit_exhaustion_of_their_token() {
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
            use_limit: Some(1),
            skip_trust: Some(true),
            ..Default::default()
        };
        let token = vault
            .setup(&host, "limited-once", "val", Some(&opts))
            .await
            .unwrap();

        // The one permitted authorization mints a handle...
        let (handle, claims, _) = vault.authorize(&token).unwrap();
        assert_eq!(claims.val, "");

        // ...and further presentations of the same token are refused: the
        // token's use-budget is exhausted.
        let err = vault.authorize(&token).unwrap_err();
        assert!(
            matches!(err, VaultError::UsageLimitExceeded { .. })
                || matches!(err, VaultError::TokenRevoked { .. }),
            "Expected UsageLimitExceeded or TokenRevoked, got: {err}"
        );

        // The original handle — minted before exhaustion — is untouched by
        // the token being refused going forward: it still resolves and its
        // secret is still readable exactly once.
        assert_eq!(vault.read_secret(&handle).unwrap().as_str(), "val");

        // "Exactly once" pinned from both sides: the second read is refused
        // as consumed, proving exhaustion did not somehow reset the
        // one-time-read state either.
        let err = vault.read_secret(&handle).unwrap_err();
        assert!(
            matches!(err, VaultError::AccessorConsumed { .. }),
            "Expected AccessorConsumed on second read, got: {err}"
        );
    }

    // -----------------------------------------------------------------
    // Issue #238: key-state persistence across process lifetimes.
    //
    // Each `VaultKeeper::init` call below models a separate process:
    // constructing a fresh `VaultKeeper` against the *same* host discards all
    // in-memory `KeyManager` state, so these tests only pass if key state is
    // actually persisted to (and hydrated from) the host's config dir rather
    // than kept in memory.
    // -----------------------------------------------------------------

    /// The scenario key persistence exists to fix: a JWE minted by one
    /// process is authorized by a later one because the `kid` it embeds still
    /// resolves to a known key.
    #[tokio::test]
    async fn a_token_minted_by_one_process_authorizes_in_a_later_process() {
        let host = TestHost::with_config();
        let first = VaultKeeper::init(
            &host,
            Some(VaultKeeperOptions {
                skip_doctor: true,
                ..Default::default()
            }),
        )
        .await
        .unwrap();
        let token = first
            .setup(
                &host,
                "cross-process",
                "s3cret",
                Some(&vaultkeeper_core::vault::SetupOptions {
                    skip_trust: Some(true),
                    ..Default::default()
                }),
            )
            .await
            .unwrap();
        drop(first);

        // A brand-new VaultKeeper against the same host simulates a fresh
        // process: without persistence its KeyManager would generate an
        // unrelated key and authorize() would fail with an unknown kid.
        let mut second = VaultKeeper::init(
            &host,
            Some(VaultKeeperOptions {
                skip_doctor: true,
                ..Default::default()
            }),
        )
        .await
        .unwrap();
        let (handle, claims, _) = second.authorize(&token).unwrap();
        assert_eq!(claims.val, "");
        assert_eq!(second.read_secret(&handle).unwrap().as_str(), "s3cret");
    }

    /// AC5: the rotation grace-period guard (`RotationInProgress`) survives a
    /// process restart because the grace-period expiry is persisted, not held
    /// only in a live timer.
    #[tokio::test]
    async fn rotation_grace_period_guard_survives_across_processes() {
        let host = TestHost::with_config();
        let mut first = VaultKeeper::init(
            &host,
            Some(VaultKeeperOptions {
                skip_doctor: true,
                ..Default::default()
            }),
        )
        .await
        .unwrap();
        first.rotate_key(&host).await.unwrap();
        drop(first);

        let mut second = VaultKeeper::init(
            &host,
            Some(VaultKeeperOptions {
                skip_doctor: true,
                ..Default::default()
            }),
        )
        .await
        .unwrap();
        let err = second.rotate_key(&host).await.unwrap_err();
        assert!(
            matches!(err, VaultError::RotationInProgress { .. }),
            "expected RotationInProgress, got: {err:?}"
        );
    }

    /// AC5: revocation is likewise persisted — a later process must not still
    /// see the revoked previous key.
    #[tokio::test]
    async fn revocation_survives_across_processes() {
        let host = TestHost::with_config();
        let mut first = VaultKeeper::init(
            &host,
            Some(VaultKeeperOptions {
                skip_doctor: true,
                ..Default::default()
            }),
        )
        .await
        .unwrap();
        first.rotate_key(&host).await.unwrap();
        first.revoke_key(&host).await.unwrap();
        drop(first);

        let mut second = VaultKeeper::init(
            &host,
            Some(VaultKeeperOptions {
                skip_doctor: true,
                ..Default::default()
            }),
        )
        .await
        .unwrap();
        // The revoked previous key's grace period must not have survived —
        // a subsequent rotation must succeed rather than reject.
        assert!(second.rotate_key(&host).await.is_ok());
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
            _options: ExecOptions<'_>,
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

// ---------------------------------------------------------------------------
// Detached-JWS signing stack tests (issue #237)
//
// @see https://www.rfc-editor.org/rfc/rfc7515#section-7.2.2 (RFC 7515 §7.2.2 detached-payload Compact JWS)
// @see https://www.rfc-editor.org/rfc/rfc7797 (RFC 7797 `b64:false` unencoded payload option)
// ---------------------------------------------------------------------------

mod signing {
    use ed25519_dalek::SigningKey;
    use ed25519_dalek::pkcs8::EncodePublicKey;
    use sha2::{Digest, Sha256};
    use std::collections::HashMap;
    use std::sync::Mutex;

    use vaultkeeper_core::backend::SigningBackend;
    use vaultkeeper_core::errors::VaultError;
    use vaultkeeper_core::signing::ed25519::{
        kid_for_verifying_key, parse_private_key_pem, parse_public_key_pem, sign as ed25519_sign,
    };
    use vaultkeeper_core::signing::{create_detached_jws, verify_detached_jws};
    use vaultkeeper_core::types::{SigningAlgorithm, SigningPublicKey, VerifyRequest};

    const TEST_PRIVATE_KEY_PEM: &str = include_str!("fixtures/signing/ed25519-test-key.pkcs8.pem");
    const TEST_PUBLIC_KEY_PEM: &str = include_str!("fixtures/signing/ed25519-test-key.spki.pem");
    const VECTORS_JSON: &str = include_str!("fixtures/signing/vectors.json");

    #[derive(serde::Deserialize)]
    struct GoldenVector {
        name: String,
        kid: String,
        #[serde(rename = "payloadBase64")]
        payload_base64: String,
        jws: String,
    }

    #[derive(serde::Deserialize)]
    struct GoldenVectorFile {
        vectors: Vec<GoldenVector>,
    }

    fn golden_vectors() -> Vec<GoldenVector> {
        let file: GoldenVectorFile =
            serde_json::from_str(VECTORS_JSON).expect("vectors.json must parse");
        file.vectors
    }

    fn decode_base64(s: &str) -> Vec<u8> {
        use base64ct::{Base64, Encoding};
        if s.is_empty() {
            return Vec::new();
        }
        Base64::decode_vec(s).expect("valid standard base64")
    }

    /// A minimal [`SigningBackend`] test double: holds one or more
    /// pre-loaded (or freshly minted) Ed25519 signing keys entirely
    /// in-memory. Deliberately NOT a production backend (no persistence,
    /// non-cryptographic deterministic key derivation in
    /// `generate_signing_key`) — it exists solely to prove
    /// `create_detached_jws` composes with the `SigningBackend` contract
    /// (AC7) without ever touching key material itself.
    struct FixtureSigningBackend {
        keys: Mutex<HashMap<String, SigningKey>>,
    }

    impl FixtureSigningBackend {
        fn new() -> Self {
            Self {
                keys: Mutex::new(HashMap::new()),
            }
        }

        /// Load the fixed, jose-interoperable test keypair under `id`.
        fn with_fixture_key(id: &str) -> Self {
            let backend = Self::new();
            let signing_key = parse_private_key_pem(TEST_PRIVATE_KEY_PEM)
                .expect("fixture private key must parse");
            backend
                .keys
                .lock()
                .expect("lock poisoned")
                .insert(id.to_string(), signing_key);
            backend
        }
    }

    #[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
    #[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
    impl vaultkeeper_core::backend::SecretBackend for FixtureSigningBackend {
        fn backend_type(&self) -> &str {
            "fixture-signing"
        }

        fn display_name(&self) -> &str {
            "Fixture Signing Backend (test-only)"
        }

        async fn is_available(&self) -> bool {
            true
        }

        async fn store(&self, _id: &str, _secret: &str) -> Result<(), VaultError> {
            Err(VaultError::Other("not a secret store".into()))
        }

        async fn retrieve(&self, _id: &str) -> Result<String, VaultError> {
            Err(VaultError::Other("not a secret store".into()))
        }

        async fn delete(&self, _id: &str) -> Result<(), VaultError> {
            Err(VaultError::Other("not a secret store".into()))
        }

        async fn exists(&self, _id: &str) -> Result<bool, VaultError> {
            Ok(false)
        }
    }

    #[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
    #[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
    impl SigningBackend for FixtureSigningBackend {
        async fn generate_signing_key(
            &self,
            id: &str,
            algorithm: SigningAlgorithm,
        ) -> Result<(), VaultError> {
            let SigningAlgorithm::EdDsa = algorithm;
            let mut keys = self.keys.lock().expect("lock poisoned");
            if keys.contains_key(id) {
                return Err(VaultError::SigningKeyAlreadyExists {
                    message: format!("signing key already exists: {id}"),
                    id: id.to_string(),
                });
            }
            // Deterministic, non-cryptographic seed derivation — acceptable
            // ONLY because this is a test double, never a real backend.
            let seed: [u8; 32] = Sha256::digest(id.as_bytes()).into();
            keys.insert(id.to_string(), SigningKey::from_bytes(&seed));
            Ok(())
        }

        async fn get_public_key(&self, id: &str) -> Result<SigningPublicKey, VaultError> {
            let keys = self.keys.lock().expect("lock poisoned");
            let signing_key = keys.get(id).ok_or_else(|| VaultError::SigningKeyNotFound {
                message: format!("signing key not found: {id}"),
                id: id.to_string(),
            })?;
            let verifying_key = signing_key.verifying_key();
            Ok(SigningPublicKey {
                public_key_pem: verifying_key
                    .to_public_key_pem(Default::default())
                    .expect("encoding an in-memory key cannot fail")
                    .to_string(),
                algorithm: SigningAlgorithm::EdDsa,
                kid: kid_for_verifying_key(&verifying_key),
            })
        }

        async fn sign_with_key(&self, id: &str, data: &[u8]) -> Result<Vec<u8>, VaultError> {
            let keys = self.keys.lock().expect("lock poisoned");
            let signing_key = keys.get(id).ok_or_else(|| VaultError::SigningKeyNotFound {
                message: format!("signing key not found: {id}"),
                id: id.to_string(),
            })?;
            Ok(ed25519_sign(signing_key, data))
        }
    }

    // --- AC4: golden-vector byte-exact equality + cross-verification ---

    #[test]
    fn golden_vector_kid_is_the_real_derived_kid_not_an_arbitrary_label() {
        // Regression for a review finding on #237: the vectors' `kid` must be
        // `base64url(sha256(spkiDer))` of the fixture public key (matching
        // `computeKid` in `packages/vaultkeeper/src/backend/file-backend.ts`
        // and the generator's own `computeKid`), not an arbitrary string —
        // otherwise the vectors don't exercise real kid derivation.
        let verifying_key = parse_public_key_pem(TEST_PUBLIC_KEY_PEM).unwrap();
        let expected_kid = kid_for_verifying_key(&verifying_key);
        for vector in golden_vectors() {
            assert_eq!(
                vector.kid, expected_kid,
                "vector '{}' must carry the fixture key's derived kid",
                vector.name
            );
        }
    }

    /// The backend's own (opaque, caller-chosen) storage identifier for the
    /// fixture key — deliberately NOT equal to any vector's `kid`. `kid` is
    /// always derived from the public key material
    /// (`base64url(sha256(spkiDer))`); the backend key id is a separate,
    /// arbitrary lookup name. Using two different values here proves
    /// `create_detached_jws` doesn't conflate them.
    const FIXTURE_BACKEND_KEY_ID: &str = "vaultkeeper-test-key-1";

    #[tokio::test]
    async fn create_detached_jws_matches_golden_vectors_byte_for_byte() {
        let backend = FixtureSigningBackend::with_fixture_key(FIXTURE_BACKEND_KEY_ID);

        for vector in golden_vectors() {
            let payload = decode_base64(&vector.payload_base64);
            let jws = create_detached_jws(&backend, &vector.kid, FIXTURE_BACKEND_KEY_ID, &payload)
                .await
                .unwrap_or_else(|e| panic!("vector '{}' failed to sign: {e}", vector.name));
            assert_eq!(
                jws, vector.jws,
                "vector '{}': Rust output must byte-exact match the jose-produced vector",
                vector.name
            );
        }
    }

    #[tokio::test]
    async fn create_detached_jws_embeds_the_derived_kid_not_the_backend_key_id() {
        // Regression for a review finding on #237: `kid` (header value,
        // derived from the public key) and the backend's own key-lookup
        // identifier are different concepts and must not be conflated.
        let backend = FixtureSigningBackend::with_fixture_key(FIXTURE_BACKEND_KEY_ID);
        let vector = golden_vectors()
            .into_iter()
            .find(|v| v.name == "ascii")
            .unwrap();
        let payload = decode_base64(&vector.payload_base64);

        let jws = create_detached_jws(&backend, &vector.kid, FIXTURE_BACKEND_KEY_ID, &payload)
            .await
            .unwrap();

        // Decode the protected header and confirm it carries the derived
        // `kid`, NOT the unrelated backend storage id.
        let parts: Vec<&str> = jws.split('.').collect();
        let header_bytes = {
            use base64ct::{Base64UrlUnpadded, Encoding};
            Base64UrlUnpadded::decode_vec(parts[0]).unwrap()
        };
        let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
        assert_eq!(header["kid"], vector.kid);
        assert_ne!(vector.kid, FIXTURE_BACKEND_KEY_ID);
    }

    #[test]
    fn verify_detached_jws_accepts_every_golden_vector() {
        for vector in golden_vectors() {
            let payload = decode_base64(&vector.payload_base64);
            let request = VerifyRequest {
                payload,
                jws: vector.jws.clone(),
                public_key: TEST_PUBLIC_KEY_PEM.to_string(),
            };
            let verified = verify_detached_jws(&request)
                .unwrap_or_else(|e| panic!("vector '{}' errored: {e}", vector.name));
            assert!(verified, "vector '{}' must verify", vector.name);
        }
    }

    #[test]
    fn verify_detached_jws_rejects_golden_vector_with_tampered_payload() {
        let vector = golden_vectors()
            .into_iter()
            .find(|v| v.name == "ascii")
            .expect("ascii vector must exist");
        let request = VerifyRequest {
            payload: b"a different payload entirely".to_vec(),
            jws: vector.jws,
            public_key: TEST_PUBLIC_KEY_PEM.to_string(),
        };
        assert!(!verify_detached_jws(&request).unwrap());
    }

    // --- AC5: negative envelope cases mirroring TS `hasExpectedHeader` ---

    /// Re-encode a golden vector's protected header with `patch` applied,
    /// keeping the same signature — used to build structurally-plausible
    /// but envelope-invalid JWS strings for the negative cases below.
    fn jws_with_patched_header(
        vector: &GoldenVector,
        patch: impl FnOnce(&mut serde_json::Map<String, serde_json::Value>),
    ) -> String {
        use base64ct::{Base64UrlUnpadded, Encoding};
        let parts: Vec<&str> = vector.jws.split('.').collect();
        let header_bytes = Base64UrlUnpadded::decode_vec(parts[0]).unwrap();
        let mut header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
        patch(header.as_object_mut().unwrap());
        let new_header_b64 =
            Base64UrlUnpadded::encode_string(&serde_json::to_vec(&header).unwrap());
        format!("{new_header_b64}..{}", parts[2])
    }

    #[test]
    fn verify_detached_jws_rejects_crit_not_exactly_b64() {
        let vector = golden_vectors()
            .into_iter()
            .find(|v| v.name == "ascii")
            .unwrap();
        let payload = decode_base64(&vector.payload_base64);
        let jws = jws_with_patched_header(&vector, |h| {
            h.insert("crit".into(), serde_json::json!(["b64", "x5t#S256"]));
        });
        let request = VerifyRequest {
            payload,
            jws,
            public_key: TEST_PUBLIC_KEY_PEM.to_string(),
        };
        assert!(!verify_detached_jws(&request).unwrap());
    }

    #[test]
    fn verify_detached_jws_rejects_alg_not_eddsa() {
        let vector = golden_vectors()
            .into_iter()
            .find(|v| v.name == "ascii")
            .unwrap();
        let payload = decode_base64(&vector.payload_base64);
        let jws = jws_with_patched_header(&vector, |h| {
            h.insert("alg".into(), serde_json::json!("RS256"));
        });
        let request = VerifyRequest {
            payload,
            jws,
            public_key: TEST_PUBLIC_KEY_PEM.to_string(),
        };
        assert!(!verify_detached_jws(&request).unwrap());
    }

    #[test]
    fn verify_detached_jws_rejects_non_empty_middle_segment() {
        let vector = golden_vectors()
            .into_iter()
            .find(|v| v.name == "ascii")
            .unwrap();
        let payload = decode_base64(&vector.payload_base64);
        let parts: Vec<&str> = vector.jws.split('.').collect();
        let jws = format!("{}.bm90LWVtcHR5.{}", parts[0], parts[2]);
        let request = VerifyRequest {
            payload,
            jws,
            public_key: TEST_PUBLIC_KEY_PEM.to_string(),
        };
        assert!(!verify_detached_jws(&request).unwrap());
    }

    #[test]
    fn verify_detached_jws_rejects_private_key_supplied_as_public() {
        let vector = golden_vectors()
            .into_iter()
            .find(|v| v.name == "ascii")
            .unwrap();
        let payload = decode_base64(&vector.payload_base64);
        let request = VerifyRequest {
            payload,
            jws: vector.jws,
            public_key: TEST_PRIVATE_KEY_PEM.to_string(),
        };
        let err = verify_detached_jws(&request).unwrap_err();
        assert!(matches!(err, VaultError::InvalidKeyMaterial { .. }));
    }

    // --- AC1/AC7: retired stale types are gone; new types compile as used above ---

    #[test]
    fn signing_public_key_and_algorithm_serialize_matching_ts_contract() {
        let key = SigningPublicKey {
            public_key_pem: "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n".into(),
            algorithm: SigningAlgorithm::EdDsa,
            kid: "abc123".into(),
        };
        let json = serde_json::to_value(&key).unwrap();
        assert_eq!(json["algorithm"], "EdDSA");
        assert!(json["publicKeyPem"].is_string());
        assert_eq!(json["kid"], "abc123");
    }

    // --- SigningBackend trait smoke tests (AC7) ---

    #[tokio::test]
    async fn signing_backend_generate_key_then_sign_round_trips() {
        let backend = FixtureSigningBackend::new();
        // "k1" is the backend's own (opaque) storage id for the key — NOT
        // the JWS `kid`, which is always the public key's derived value
        // (mirrors `VaultKeeper.sign` calling
        // `createDetachedJws(claims.kid, payload, (data) =>
        // backend.signWithKey(claims.backendRef, data))` in vault.ts).
        const BACKEND_KEY_ID: &str = "k1";
        backend
            .generate_signing_key(BACKEND_KEY_ID, SigningAlgorithm::EdDsa)
            .await
            .unwrap();
        let public_key = backend.get_public_key(BACKEND_KEY_ID).await.unwrap();
        let verifying_key = parse_public_key_pem(&public_key.public_key_pem).unwrap();

        let jws = create_detached_jws(&backend, &public_key.kid, BACKEND_KEY_ID, b"payload bytes")
            .await
            .unwrap();
        let request = VerifyRequest {
            payload: b"payload bytes".to_vec(),
            jws,
            public_key: public_key.public_key_pem.clone(),
        };
        assert!(verify_detached_jws(&request).unwrap());
        // Sanity: the kid embedded matches the public key's own kid.
        assert_eq!(public_key.kid, kid_for_verifying_key(&verifying_key));
    }

    #[tokio::test]
    async fn signing_backend_rejects_duplicate_generate() {
        let backend = FixtureSigningBackend::new();
        backend
            .generate_signing_key("k1", SigningAlgorithm::EdDsa)
            .await
            .unwrap();
        let err = backend
            .generate_signing_key("k1", SigningAlgorithm::EdDsa)
            .await
            .unwrap_err();
        assert!(matches!(err, VaultError::SigningKeyAlreadyExists { .. }));
    }

    #[tokio::test]
    async fn signing_backend_sign_with_unknown_key_errors() {
        let backend = FixtureSigningBackend::new();
        let err = backend.sign_with_key("missing", b"data").await.unwrap_err();
        assert!(matches!(err, VaultError::SigningKeyNotFound { .. }));
    }

    #[tokio::test]
    async fn create_detached_jws_propagates_signing_key_not_found() {
        let backend = FixtureSigningBackend::new();
        let err = create_detached_jws(&backend, "some-kid", "missing", b"data")
            .await
            .unwrap_err();
        assert!(matches!(err, VaultError::SigningKeyNotFound { .. }));
    }
}
