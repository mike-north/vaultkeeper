//! VaultKeeper main struct — wires together all vaultkeeper subsystems.

use std::collections::HashMap;

use crate::backend::{HostPlatform, SecretBackend};
use crate::config;
use crate::errors::VaultError;
use crate::jwe::{
    CreateTokenOptions, block_token, create_token, decrypt_token, extract_kid, validate_claims,
};
use crate::keys::KeyManager;
use crate::types::{KeyStatus, PreflightResult, VaultClaims, VaultConfig, VaultResponse};

/// Options for initializing VaultKeeper.
#[derive(Debug, Default)]
pub struct VaultKeeperOptions {
    /// Supply config directly, skipping file load.
    pub config: Option<VaultConfig>,
    /// Skip the doctor preflight check.
    pub skip_doctor: bool,
}

/// Options for the setup operation.
///
/// `setup()` requires an explicit executable-trust decision: supply exactly one
/// of [`SetupOptions::executable_path`] (bind the token to the calling
/// executable) or [`SetupOptions::skip_trust`] (a development-only opt-out).
/// Supplying neither, both, or the retired `"dev"` sentinel as
/// `executable_path` fails with [`VaultError::ExecutableTrustRequired`].
#[derive(Debug, Default)]
pub struct SetupOptions {
    /// TTL in minutes for the JWE.
    pub ttl_minutes: Option<u32>,
    /// Usage limit (`None` for unlimited).
    pub use_limit: Option<u64>,
    /// Executable path to bind the token to (the calling executable's real
    /// path). Mutually exclusive with [`SetupOptions::skip_trust`]. The retired
    /// `"dev"` sentinel is rejected — use `skip_trust: Some(true)` instead.
    pub executable_path: Option<String>,
    /// Development-only opt-out that deliberately skips executable-trust binding,
    /// producing a `"dev"`-bound (unverified) token. Mutually exclusive with
    /// [`SetupOptions::executable_path`].
    pub skip_trust: Option<bool>,
    /// Trust tier override.
    pub trust_tier: Option<crate::types::TrustTier>,
    /// Backend type to use.
    pub backend_type: Option<String>,
}

/// Main entry point for vaultkeeper. Orchestrates backends, keys, JWE tokens,
/// identity verification, and access patterns.
pub struct VaultKeeper {
    config: VaultConfig,
    key_manager: KeyManager,
    _backend: Option<Box<dyn SecretBackend>>,
    /// Per-JTI usage counts for use-limited tokens.
    usage_counts: HashMap<String, u64>,
}

impl VaultKeeper {
    /// Initialize a new VaultKeeper instance.
    ///
    /// Runs doctor checks (unless skipped), loads config, and sets up the key manager.
    pub async fn init(
        host: &dyn HostPlatform,
        options: Option<VaultKeeperOptions>,
    ) -> Result<Self, VaultError> {
        let opts = options.unwrap_or_default();

        let cfg = match opts.config {
            Some(c) => c,
            None => config::load_config(host).await?,
        };

        if !opts.skip_doctor {
            let doctor_result = crate::doctor::run_doctor(host, Some(&cfg.backends)).await;
            if !doctor_result.ready {
                return Err(VaultError::Other(format!(
                    "System not ready: {}",
                    doctor_result.next_steps.join("; ")
                )));
            }
        }

        let mut key_manager = KeyManager::new();
        key_manager.init()?;

        Ok(Self {
            config: cfg,
            key_manager,
            _backend: None,
            usage_counts: HashMap::new(),
        })
    }

    /// Run doctor checks without full initialization.
    ///
    /// Uses conservative platform defaults — all platform-native dependency
    /// checks are treated as required regardless of any backend configuration.
    /// For config-aware scoping, call `run_doctor` with `Some(backends)`.
    pub async fn doctor(host: &dyn HostPlatform) -> PreflightResult {
        crate::doctor::run_doctor(host, None).await
    }

    /// Get a reference to the current config.
    pub fn config(&self) -> &VaultConfig {
        &self.config
    }

    /// Get a reference to the key manager.
    pub fn key_manager(&self) -> &KeyManager {
        &self.key_manager
    }

    /// Get a mutable reference to the key manager.
    pub fn key_manager_mut(&mut self) -> &mut KeyManager {
        &mut self.key_manager
    }

    /// Rotate the current encryption key.
    pub fn rotate_key(&mut self) -> Result<(), VaultError> {
        let grace_period_ms =
            u64::from(self.config.key_rotation.grace_period_days) * 24 * 60 * 60 * 1000;
        self.key_manager.rotate_key(grace_period_ms)
    }

    /// Emergency key revocation.
    pub fn revoke_key(&mut self) -> Result<(), VaultError> {
        self.key_manager.revoke_key()
    }

    /// Store a secret value and produce a JWE token encapsulating it.
    ///
    /// The returned compact JWE string can be passed to `authorize()` or
    /// the CLI `exec` command to retrieve the secret.
    ///
    /// The caller must make an explicit executable-trust decision via
    /// [`SetupOptions`]: supply exactly one of
    /// [`SetupOptions::executable_path`] (bind the token to a real executable)
    /// or [`SetupOptions::skip_trust`] (a development-only opt-out). Supplying
    /// neither, both, or the retired `"dev"` sentinel as `executable_path`
    /// returns [`VaultError::ExecutableTrustRequired`] rather than silently
    /// minting an unverified `"dev"`-bound token.
    pub fn setup(
        &self,
        secret_name: &str,
        secret_value: &str,
        options: Option<&SetupOptions>,
    ) -> Result<String, VaultError> {
        let ttl_minutes = options
            .and_then(|o| o.ttl_minutes)
            .unwrap_or(self.config.defaults.ttl_minutes);
        let use_limit = options.and_then(|o| o.use_limit);
        let exe = Self::resolve_executable_identity(options)?;
        let trust_tier = options
            .and_then(|o| o.trust_tier)
            .unwrap_or(self.config.defaults.trust_tier);
        let backend_type = options
            .and_then(|o| o.backend_type.as_deref())
            .unwrap_or("file")
            .to_string();

        let now = crate::util::time::now_secs();

        let claims = VaultClaims {
            jti: uuid::Uuid::new_v4().to_string(),
            exp: now + u64::from(ttl_minutes) * 60,
            iat: now,
            sub: secret_name.to_string(),
            exe,
            use_limit,
            tid: trust_tier,
            bkd: backend_type,
            val: secret_value.to_string(),
            reference: secret_name.to_string(),
        };

        let current_key = self.key_manager.get_current_key()?;
        create_token(
            &current_key.key,
            &claims,
            &CreateTokenOptions {
                kid: Some(current_key.id.clone()),
            },
        )
    }

    /// Resolve the executable identity to bind into a token, requiring an
    /// explicit trust decision from the caller.
    ///
    /// Returns the sentinel `"dev"` (no executable binding) when trust is
    /// deliberately skipped; otherwise returns the caller-supplied executable
    /// path. Returns [`VaultError::ExecutableTrustRequired`] when the caller
    /// makes no unambiguous choice — mirroring the TypeScript library's
    /// `ExecutableTrustRequiredError` (message + `reason` discriminator).
    fn resolve_executable_identity(options: Option<&SetupOptions>) -> Result<String, VaultError> {
        let executable_path = options.and_then(|o| o.executable_path.as_deref());
        let skip_trust = options.and_then(|o| o.skip_trust).unwrap_or(false);

        if skip_trust && executable_path.is_some() {
            return Err(VaultError::ExecutableTrustRequired {
                message: "VaultKeeper.setup() received both options.executablePath and \
                          options.skipTrust: true, which are mutually exclusive. Pass \
                          options.executablePath to verify the calling executable, or \
                          options.skipTrust: true to skip verification (development only) — not both."
                    .to_string(),
                reason: "conflicting-choice".to_string(),
            });
        }

        if skip_trust {
            // Explicit, greppable development-only opt-out: no executable identity
            // is bound.
            return Ok("dev".to_string());
        }

        match executable_path {
            None => Err(VaultError::ExecutableTrustRequired {
                message: "VaultKeeper.setup() requires an explicit executable-trust choice and \
                          no longer defaults to skipping verification. Either pass \
                          options.executablePath set to the calling executable's real path \
                          (runs trust-on-first-use verification), or set options.skipTrust: \
                          true to deliberately skip verification (development only)."
                    .to_string(),
                reason: "missing-choice".to_string(),
            }),
            // Reject the retired legacy opt-out sentinel. Before explicit-trust,
            // options.executablePath: "dev" was the documented way to skip
            // verification; point migrating callers at the dedicated opt-out.
            Some("dev") => Err(VaultError::ExecutableTrustRequired {
                message: "VaultKeeper.setup() no longer supports the legacy options.executablePath: 'dev' \
                          sentinel for skipping trust verification. Set options.skipTrust: true to \
                          deliberately skip verification (development only), or pass \
                          options.executablePath set to the calling executable's real path to verify it."
                    .to_string(),
                reason: "legacy-dev-sentinel".to_string(),
            }),
            Some(path) => Ok(path.to_string()),
        }
    }

    /// Decrypt a JWE token, validate its claims, and return the claims
    /// and key status. Tracks per-JTI usage counts and blocks tokens that
    /// exceed their use limit.
    pub fn authorize(&mut self, jwe: &str) -> Result<(VaultClaims, VaultResponse), VaultError> {
        let kid = extract_kid(jwe)?;

        let (key, is_current) = match &kid {
            Some(k) => {
                self.key_manager
                    .find_key_by_id(k)
                    .ok_or_else(|| VaultError::KeyRevoked {
                        message: format!("Unknown key ID: {k}"),
                    })?
            }
            None => {
                let k = self.key_manager.get_current_key()?;
                (k, true)
            }
        };

        let claims = decrypt_token(&key.key, jwe)?;

        let current_usage = self.usage_counts.get(&claims.jti).copied().unwrap_or(0);
        validate_claims(&claims, current_usage)?;

        // Increment usage count
        let new_usage = current_usage + 1;
        self.usage_counts.insert(claims.jti.clone(), new_usage);

        // If usage limit reached, block the token for future requests
        if let Some(limit) = claims.use_limit
            && new_usage >= limit
        {
            block_token(&claims.jti);
        }

        let key_status = if is_current {
            KeyStatus::Current
        } else {
            KeyStatus::Previous
        };

        let mut response = VaultResponse {
            key_status,
            rotated_jwt: None,
        };

        // If decrypted with previous key, re-encrypt with current
        if !is_current {
            let current_key = self.key_manager.get_current_key()?;
            let rotated = create_token(
                &current_key.key,
                &claims,
                &CreateTokenOptions {
                    kid: Some(current_key.id.clone()),
                },
            )?;
            response.rotated_jwt = Some(rotated);
        }

        Ok((claims, response))
    }
}
