//! Shared types and interfaces for vaultkeeper.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use zeroize::Zeroize;

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

/// A [`PreflightCheck`] scoped by whether its dependency is required for the
/// active/configured backend(s). Plugin-backend checks (`op`, `ykman`) are
/// `required: false` when their backend isn't enabled — a non-`Ok` status
/// there is informational, not a system-readiness blocker (issue #116). They
/// are promoted to `required: true` when their backend is explicitly enabled
/// (e.g. the `yubikey` backend requires `ykman`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScopedPreflightCheck {
    /// The underlying check result. Flattened so the JSON/JS shape is
    /// identical to a plain `PreflightCheck` with an added `required` field.
    #[serde(flatten)]
    pub check: PreflightCheck,
    /// Whether this dependency is required by the active/configured backend(s).
    pub required: bool,
}

/// Aggregated result from all preflight checks.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreflightResult {
    /// Individual check results, one per dependency inspected.
    pub checks: Vec<ScopedPreflightCheck>,
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
#[serde(rename_all = "camelCase")]
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
#[serde(rename_all = "camelCase")]
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
        buf.zeroize();
        Ok(result)
    }
}

impl Drop for SecretAccessor {
    fn drop(&mut self) {
        if let Some(ref mut buf) = self.secret {
            buf.zeroize();
        }
    }
}

/// A signing algorithm identifier from the strict JOSE registry (RFC 7518).
///
/// Only `EdDSA` (Ed25519) is supported today; the identifier is intentionally
/// a strict JOSE `alg` value so future algorithms (`ES256`, `RS256`, …) each
/// bind to their proper curve/key type rather than an ambiguous label. Mirrors
/// the TypeScript `SigningAlgorithm` (`packages/vaultkeeper/src/types.ts`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SigningAlgorithm {
    /// Ed25519 (the sole supported algorithm).
    #[serde(rename = "EdDSA")]
    EdDsa,
}

/// The public half of an enrolled signing key.
///
/// Mirrors the TypeScript `SigningPublicKey` (`packages/vaultkeeper/src/types.ts`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SigningPublicKey {
    /// SPKI (SubjectPublicKeyInfo) PEM encoding of the public key.
    pub public_key_pem: String,
    /// The JOSE algorithm this key signs with.
    pub algorithm: SigningAlgorithm,
    /// Stable key identifier: the base64url-encoded SHA-256 of the SPKI DER.
    /// Used as the JWS `kid` protected-header value so a verifier can select
    /// the key.
    pub kid: String,
}

/// Request for detached-signature verification (RFC 7515 §7.2.2 + RFC 7797).
///
/// This is a fully offline operation that only requires public key
/// material — no `VaultKeeper` instance, backend, config, or capability token
/// is needed. Mirrors the TypeScript `VerifyRequest`
/// (`packages/vaultkeeper/src/types.ts`); replaces the stale, never-shipped
/// generic hash+sign `VerifyRequest` this crate carried before issue #237.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyRequest {
    /// The detached payload bytes that were signed.
    pub payload: Vec<u8>,
    /// The detached-payload compact JWS (`<protected>..<signature>`) produced
    /// by [`crate::signing::create_detached_jws`].
    pub jws: String,
    /// PEM-encoded public key (SPKI format).
    pub public_key: String,
}

/// Vaultkeeper configuration file structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
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
#[serde(rename_all = "camelCase")]
pub struct KeyRotationPolicy {
    /// Number of days the previous key remains valid after rotation.
    pub grace_period_days: u32,
}

/// Default values for vault operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultDefaults {
    /// Default JWE time-to-live in minutes.
    pub ttl_minutes: u32,
    /// Default trust tier for executable identity verification.
    ///
    /// In `config.json` this field is written as a bare JSON number
    /// (`"trustTier": 3`), matching the CLI `config init` output, the TS
    /// library, and the README example. For backward compatibility the reader
    /// also accepts a string-encoded number (`"trustTier": "3"`), which older
    /// native-CLI configs emitted. Note this differs from the `tid` claim in a
    /// JWE token, where [`TrustTier`] keeps its string wire form (`"3"`) for
    /// `jose` compatibility.
    #[serde(with = "trust_tier_config")]
    pub trust_tier: TrustTier,
}

/// Serde adapter for the `defaults.trustTier` config field (issue #200).
///
/// Serializes [`TrustTier`] as a bare JSON number and deserializes leniently
/// from either a JSON number or a string-encoded number, so a config written
/// by any of the CLIs (TS or native) loads uniformly. Kept local to the config
/// field so the string wire form of [`TrustTier`] in JWE claims is untouched.
mod trust_tier_config {
    use super::TrustTier;
    use serde::de::{Error as DeError, Unexpected};
    use serde::{Deserialize, Deserializer, Serializer};

    fn tier_from_u64<E: DeError>(n: u64, unexpected: Unexpected<'_>) -> Result<TrustTier, E> {
        match n {
            1 => Ok(TrustTier::Sigstore),
            2 => Ok(TrustTier::Tofu),
            3 => Ok(TrustTier::Dev),
            _ => Err(E::invalid_value(unexpected, &"a trust tier of 1, 2, or 3")),
        }
    }

    pub(super) fn serialize<S>(value: &TrustTier, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u8(*value as u8)
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<TrustTier, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum NumberOrString {
            Number(u64),
            String(String),
        }

        match NumberOrString::deserialize(deserializer)? {
            NumberOrString::Number(n) => tier_from_u64(n, Unexpected::Unsigned(n)),
            NumberOrString::String(s) => {
                let trimmed = s.trim();
                let n: u64 = trimmed.parse().map_err(|_| {
                    D::Error::invalid_value(
                        Unexpected::Str(&s),
                        &"a trust tier of \"1\", \"2\", or \"3\"",
                    )
                })?;
                tier_from_u64(n, Unexpected::Str(&s))
            }
        }
    }
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
