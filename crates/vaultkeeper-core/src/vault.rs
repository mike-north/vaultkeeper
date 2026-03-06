//! VaultKeeper main struct — wires together all vaultkeeper subsystems.

use crate::backend::{HostPlatform, SecretBackend};
use crate::config;
use crate::errors::VaultError;
use crate::jwe::{create_token, decrypt_token, extract_kid, validate_claims, CreateTokenOptions};
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
#[derive(Debug, Default)]
pub struct SetupOptions {
    /// TTL in minutes for the JWE.
    pub ttl_minutes: Option<u32>,
    /// Usage limit (`None` for unlimited).
    pub use_limit: Option<u64>,
    /// Executable path for identity binding. Use `"dev"` for dev mode.
    pub executable_path: Option<String>,
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

        if !opts.skip_doctor {
            let doctor_result = crate::doctor::run_doctor(host).await;
            if !doctor_result.ready {
                return Err(VaultError::Other(format!(
                    "System not ready: {}",
                    doctor_result.next_steps.join("; ")
                )));
            }
        }

        let cfg = match opts.config {
            Some(c) => c,
            None => config::load_config(host).await?,
        };

        let mut key_manager = KeyManager::new();
        key_manager.init()?;

        Ok(Self {
            config: cfg,
            key_manager,
            _backend: None,
        })
    }

    /// Run doctor checks without full initialization.
    pub async fn doctor(host: &dyn HostPlatform) -> PreflightResult {
        crate::doctor::run_doctor(host).await
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
        let exe = options
            .and_then(|o| o.executable_path.as_deref())
            .unwrap_or("dev")
            .to_string();
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

    /// Decrypt a JWE token, validate its claims, and return the claims
    /// and key status.
    pub fn authorize(&self, jwe: &str) -> Result<(VaultClaims, VaultResponse), VaultError> {
        let kid = extract_kid(jwe)?;

        let (key, is_current) = match &kid {
            Some(k) => self
                .key_manager
                .find_key_by_id(k)
                .ok_or_else(|| VaultError::Other(format!("Unknown key ID: {k}")))?,
            None => {
                let k = self.key_manager.get_current_key()?;
                (k, true)
            }
        };

        let claims = decrypt_token(&key.key, jwe)?;
        validate_claims(&claims, 0)?;

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
