//! VaultKeeper main struct — wires together all vaultkeeper subsystems.

use crate::backend::{HostPlatform, SecretBackend};
use crate::config;
use crate::errors::VaultError;
use crate::keys::KeyManager;
use crate::types::{PreflightResult, VaultConfig};

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
}
