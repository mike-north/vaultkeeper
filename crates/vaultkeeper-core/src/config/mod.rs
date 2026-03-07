//! Configuration loading, validation, and defaults.

use crate::errors::VaultError;
use crate::types::{BackendConfig, KeyRotationPolicy, TrustTier, VaultConfig, VaultDefaults};

/// Return the default configuration when no config file exists.
///
/// The default backend is chosen based on the target platform:
/// - macOS: `keychain` (Keychain Services)
/// - Windows: `dpapi` (Data Protection API)
/// - Linux / other Unix: `file` (encrypted file backend)
///
/// The `file` backend is preferred over `secret-tool` on Linux because
/// `secret-tool` requires `libsecret-tools` which is not universally installed.
pub fn default_config() -> VaultConfig {
    let backend = if cfg!(target_os = "macos") {
        BackendConfig {
            backend_type: "keychain".to_string(),
            enabled: true,
            plugin: None,
            path: None,
            options: None,
        }
    } else if cfg!(target_os = "windows") {
        BackendConfig {
            backend_type: "dpapi".to_string(),
            enabled: true,
            plugin: None,
            path: None,
            options: None,
        }
    } else {
        // Linux and other Unix-like systems.
        BackendConfig {
            backend_type: "file".to_string(),
            enabled: true,
            plugin: None,
            path: None,
            options: None,
        }
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
