//! Configuration loading, validation, and defaults.

use crate::backend::Platform;
use crate::errors::VaultError;
use crate::types::{BackendConfig, KeyRotationPolicy, TrustTier, VaultConfig, VaultDefaults};

/// The zero-config default backend type — the `file` backend, on every
/// platform.
///
/// This is deliberately **not** platform-native (`keychain` on macOS, `dpapi`
/// on Windows): a missing config must never silently target the real OS
/// keychain/credential store (see #98). Explicit configuration may still
/// select `keychain`/`dpapi`/`secret-tool` — this only governs the fallback
/// used when no config file exists. Mirrors `defaultBackendType()` in
/// `packages/vaultkeeper/src/config.ts`.
pub const DEFAULT_BACKEND_TYPE: &str = "file";

/// Return the zero-config default backend type for a given platform.
///
/// Always [`DEFAULT_BACKEND_TYPE`], regardless of `platform` — see
/// [`DEFAULT_BACKEND_TYPE`] for why. The `platform` parameter exists so
/// regression tests can iterate every [`Platform`] arm explicitly rather than
/// relying on `cfg!(target_os = ...)`, which only exercises one arm per host
/// (#98 / #235).
#[must_use]
pub fn default_backend_type_for_platform(_platform: Platform) -> &'static str {
    DEFAULT_BACKEND_TYPE
}

/// Return the default configuration when no config file exists.
///
/// The zero-config default backend is always [`DEFAULT_BACKEND_TYPE`]
/// (`file`) — see its docs for why the platform is never consulted here.
pub fn default_config() -> VaultConfig {
    let backend = BackendConfig {
        backend_type: DEFAULT_BACKEND_TYPE.to_string(),
        enabled: true,
        plugin: None,
        path: None,
        options: None,
    };

    VaultConfig {
        version: 1,
        backends: vec![backend],
        key_rotation: KeyRotationPolicy {
            grace_period_days: 7,
        },
        defaults: VaultDefaults {
            ttl_minutes: 60,
            trust_tier: TrustTier::Dev,
        },
        development_mode: None,
    }
}

/// Validate a parsed config value.
///
/// # Errors
/// Returns `VaultError` if the config structure is invalid.
pub fn validate_config(config: &VaultConfig) -> Result<(), VaultError> {
    if config.version != 1 {
        return Err(VaultError::Other("Config version must be 1".to_string()));
    }

    if config.backends.is_empty() {
        return Err(VaultError::Other(
            "Config must have at least one backend".to_string(),
        ));
    }

    for (i, backend) in config.backends.iter().enumerate() {
        if backend.backend_type.trim().is_empty() {
            return Err(VaultError::Other(format!(
                "backends[{i}].type must be a non-empty string"
            )));
        }
    }

    if config.key_rotation.grace_period_days == 0 {
        return Err(VaultError::Other(
            "Config keyRotation.gracePeriodDays must be a positive number".to_string(),
        ));
    }

    if config.defaults.ttl_minutes == 0 {
        return Err(VaultError::Other(
            "Config defaults.ttlMinutes must be a positive number".to_string(),
        ));
    }

    if let Some(ref dev_mode) = config.development_mode {
        for (i, exe) in dev_mode.executables.iter().enumerate() {
            if exe.trim().is_empty() {
                return Err(VaultError::Other(format!(
                    "Config developmentMode.executables[{i}] must be a non-empty string"
                )));
            }
        }
    }

    Ok(())
}

/// Load config from a JSON string, falling back to defaults if empty.
///
/// # Errors
/// Returns `VaultError` if parsing or validation fails.
pub fn load_config_from_str(json: &str) -> Result<VaultConfig, VaultError> {
    if json.trim().is_empty() {
        return Ok(default_config());
    }

    let config: VaultConfig = serde_json::from_str(json)
        .map_err(|e| VaultError::Other(format!("Failed to parse config: {e}")))?;

    validate_config(&config)?;
    Ok(config)
}

/// Load config using a [`HostPlatform`] to read from disk.
///
/// Falls back to [`default_config()`] if the file does not exist.
pub async fn load_config(
    host: &dyn crate::backend::HostPlatform,
) -> Result<VaultConfig, VaultError> {
    let config_path = host.config_dir().join("config.json");

    match host.file_exists(&config_path).await {
        Ok(true) => {}
        _ => return Ok(default_config()),
    }

    let content = host.read_file(&config_path).await?;
    let json = String::from_utf8(content)
        .map_err(|e| VaultError::Other(format!("Invalid UTF-8 in config: {e}")))?;

    load_config_from_str(&json)
}
