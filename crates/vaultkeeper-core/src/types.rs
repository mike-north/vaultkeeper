//! Shared types and interfaces for vaultkeeper.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Trust tier for executable identity verification.
///
/// - Tier 1: Sigstore-verified
/// - Tier 2: TOFU hash-verified
/// - Tier 3: Unverified / dev mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TrustTier {
    /// Sigstore-verified identity.
    #[serde(rename = "1")]
    Sigstore = 1,
    /// TOFU hash-verified identity.
    #[serde(rename = "2")]
    Tofu = 2,
    /// Unverified / development mode.
    #[serde(rename = "3")]
    Dev = 3,
}

/// Key status in the rotation lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyStatus {
    Current,
    Previous,
    Deprecated,
}

/// Status of a preflight check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PreflightCheckStatus {
    Ok,
    Missing,
    VersionUnsupported,
}

/// Result of a preflight check for a single dependency.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreflightCheck {
    /// Human-readable name of the dependency being checked.
    pub name: String,
    /// Whether the dependency was found and is a supported version.
    pub status: PreflightCheckStatus,
    /// The detected version string, if found.
    pub version: Option<String>,
    /// Human-readable explanation of why the status is not `Ok`.
    pub reason: Option<String>,
}

/// Aggregated result from all preflight checks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreflightResult {
    /// Individual check results, one per dependency inspected.
    pub checks: Vec<PreflightCheck>,
    /// `true` if all required checks passed and the system is ready.
    pub ready: bool,
    /// Non-fatal advisory messages about optional missing dependencies.
    pub warnings: Vec<String>,
    /// Action items the user should complete before vaultkeeper will work.
    pub next_steps: Vec<String>,
}

/// JWE claim payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultClaims {
    /// Unique token ID.
    pub jti: String,
    /// Expiration (Unix timestamp).
    pub exp: u64,
    /// Issued-at (Unix timestamp).
    pub iat: u64,
    /// Secret reference path.
    pub sub: String,
    /// Executable identity hash or `"dev"`.
    pub exe: String,
    /// Usage limit (`None` for unlimited).
    #[serde(rename = "use")]
    pub use_limit: Option<u64>,
    /// Trust tier.
    pub tid: TrustTier,
    /// Backend identifier hint.
    pub bkd: String,
    /// Encrypted secret value.
    pub val: String,
    /// Backend-specific reference path.
    #[serde(rename = "ref")]
    pub reference: String,
}

/// Response from a vault access operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultResponse {
    /// Replacement JWE if key was rotated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rotated_jwt: Option<String>,
    /// Current key status.
    pub key_status: KeyStatus,
}

/// Request for delegated HTTP fetch.
///
/// String values may include `{{secret}}`, which is replaced with the actual
/// secret value immediately before the request is sent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FetchRequest {
    /// The target URL. May contain `{{secret}}`.
    pub url: String,
    /// HTTP method (defaults to `"GET"` when `None`).
    pub method: Option<String>,
    /// Request headers. Values may contain `{{secret}}`.
    pub headers: Option<HashMap<String, String>>,
    /// Request body. May contain `{{secret}}`.
    pub body: Option<String>,
}

/// Request for delegated command execution.
///
/// String values may include `{{secret}}`, which is replaced with the actual
/// secret value immediately before the command is spawned.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecRequest {
    /// The command (binary) to execute.
    pub command: String,
    /// Command-line arguments. Values may contain `{{secret}}`.
    pub args: Option<Vec<String>>,
    /// Additional environment variables. Values may contain `{{secret}}`.
    pub env: Option<HashMap<String, String>>,
    /// Working directory for the spawned process.
    pub cwd: Option<String>,
}

/// Result from delegated command execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecResult {
    /// Captured standard output.
    pub stdout: String,
    /// Captured standard error.
    pub stderr: String,
    /// Process exit code.
    pub exit_code: i32,
}

/// Callback-based secret accessor with auto-zeroing.
///
/// In Rust, the accessor provides a one-time `read()` that passes a byte slice
/// containing the secret. The backing memory is zeroed after the callback returns.
pub struct SecretAccessor {
    /// The secret value (zeroed after first read).
    secret: Option<Vec<u8>>,
}

impl SecretAccessor {
    /// Create a new accessor wrapping the given secret.
    pub fn new(secret: Vec<u8>) -> Self {
        Self {
            secret: Some(secret),
        }
    }

    /// Read the secret via a callback. The secret is zeroed after the callback returns.
    /// Returns `Err` if the accessor has already been consumed.
    pub fn read<F, R>(&mut self, callback: F) -> Result<R, crate::errors::VaultError>
    where
        F: FnOnce(&[u8]) -> R,
    {
        let mut buf = self.secret.take().ok_or(crate::errors::VaultError::Other(
            "SecretAccessor already consumed".to_string(),
        ))?;
        let result = callback(&buf);
        // Zero the buffer
        buf.iter_mut().for_each(|b| *b = 0);
        Ok(result)
    }
}

impl Drop for SecretAccessor {
    fn drop(&mut self) {
        if let Some(ref mut buf) = self.secret {
            buf.iter_mut().for_each(|b| *b = 0);
        }
    }
}

/// Request for delegated signing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignRequest {
    /// The data to sign (UTF-8 string).
    pub data: String,
    /// Override the hash algorithm (`"sha256"`, `"sha384"`, or `"sha512"`).
    pub algorithm: Option<String>,
}

/// Result from a delegated signing operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignResult {
    /// Base64-encoded signature.
    pub signature: String,
    /// Algorithm label describing how the signature was produced.
    pub algorithm: String,
}

/// Request for signature verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyRequest {
    /// The original data that was signed (UTF-8 string).
    pub data: String,
    /// Base64-encoded signature to verify.
    pub signature: String,
    /// PEM-encoded public key (SPKI format).
    pub public_key: String,
    /// Override the hash algorithm.
    pub algorithm: Option<String>,
}

/// Vaultkeeper configuration file structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultConfig {
    /// Config schema version. Currently must be `1`.
    pub version: u32,
    /// Ordered list of backend configurations.
    pub backends: Vec<BackendConfig>,
    /// Key rotation policy.
    pub key_rotation: KeyRotationPolicy,
    /// Default values applied to `setup()` when options are not provided.
    pub defaults: VaultDefaults,
    /// Development mode configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub development_mode: Option<DevelopmentMode>,
}

/// Key rotation policy configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRotationPolicy {
    /// Number of days the previous key remains valid after rotation.
    pub grace_period_days: u32,
}

/// Default values for vault operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultDefaults {
    /// Default JWE time-to-live in minutes.
    pub ttl_minutes: u32,
    /// Default trust tier for executable identity verification.
    pub trust_tier: TrustTier,
}

/// Development mode configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevelopmentMode {
    /// Paths of executables that bypass identity verification.
    pub executables: Vec<String>,
}

/// Configuration for a single backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendConfig {
    /// Backend type identifier (e.g. `"keychain"`, `"file"`, `"1password"`).
    #[serde(rename = "type")]
    pub backend_type: String,
    /// Whether this backend is active.
    pub enabled: bool,
    /// Whether this backend is provided by an external plugin.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plugin: Option<bool>,
    /// Filesystem path used by file-based backends.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Backend-specific options.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<HashMap<String, String>>,
}
