//! Error hierarchy for vaultkeeper.
//!
//! All errors derive from [`VaultError`]. Each variant carries structured context
//! for machine-readable error handling.

/// Base error type for all vaultkeeper operations.
#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    // --- Backend Access Failures ---
    /// The backend keychain or credential store is locked.
    #[error("{message}")]
    BackendLocked {
        message: String,
        /// Whether the lock can be resolved through an interactive prompt.
        interactive: bool,
    },

    /// A hardware device required for authentication is not connected.
    #[error("{message}")]
    DeviceNotPresent {
        message: String,
        /// How long (ms) the operation waited before giving up.
        timeout_ms: u64,
    },

    /// The user explicitly denied an authorization request.
    #[error("{message}")]
    AuthorizationDenied { message: String },

    /// No configured backend is available or reachable.
    #[error("{message}")]
    BackendUnavailable {
        message: String,
        /// Machine-readable reason code (e.g. `"none-enabled"`, `"all-failed"`).
        reason: String,
        /// Backend type identifiers that were attempted.
        attempted: Vec<String>,
    },

    /// A required backend plugin is not installed.
    #[error("{message}")]
    PluginNotFound {
        message: String,
        /// The plugin package or binary name.
        plugin: String,
        /// URL pointing to installation instructions.
        install_url: String,
    },

    /// A requested secret does not exist in the backend store.
    #[error("{message}")]
    SecretNotFound { message: String },

    /// A stored secret entry could not be decrypted — the ciphertext is
    /// corrupted/truncated or the AES-GCM authentication tag failed to verify.
    #[error("{message}")]
    Decryption {
        message: String,
        /// The path of the encrypted entry that failed to decrypt.
        path: String,
    },

    // --- JWE Lifecycle Failures ---
    /// A JWE token has passed its expiration time.
    #[error("{message}")]
    TokenExpired {
        message: String,
        /// Whether the token can be refreshed by calling `setup()` again.
        can_refresh: bool,
    },

    /// The encryption key used for a JWE has been rotated out of the grace period.
    #[error("{message}")]
    KeyRotated { message: String },

    /// The encryption key has been explicitly revoked.
    #[error("{message}")]
    KeyRevoked { message: String },

    /// A JWE token has been explicitly blocked.
    #[error("{message}")]
    TokenRevoked { message: String },

    /// A token with a finite use limit has exceeded that limit.
    #[error("{message}")]
    UsageLimitExceeded { message: String },

    // --- Identity and Trust Failures ---
    /// Executable hash no longer matches the previously approved hash (TOFU conflict).
    #[error("{message}")]
    IdentityMismatch {
        message: String,
        /// Hash recorded at approval time.
        previous_hash: String,
        /// Hash computed from the current executable.
        current_hash: String,
    },

    /// `setup()` was called without an unambiguous executable-trust decision.
    ///
    /// Mirrors the TypeScript `vaultkeeper` library's `ExecutableTrustRequiredError`:
    /// the caller must supply exactly one of an executable path (to bind) or an
    /// explicit skip; supplying neither, both, or the retired `"dev"` sentinel
    /// fails here instead of silently minting an unbound token.
    #[error("{message}")]
    ExecutableTrustRequired {
        message: String,
        /// Machine-readable discriminator for why the trust choice was rejected.
        /// See [`ExecutableTrustRequiredReason`].
        reason: ExecutableTrustRequiredReason,
    },

    // --- Infrastructure Failures ---
    /// A disallowed signing/verification algorithm was requested.
    #[error("{message}")]
    InvalidAlgorithm {
        message: String,
        /// The algorithm that was requested.
        algorithm: String,
        /// The set of algorithms that are allowed.
        allowed: Vec<String>,
    },

    /// A required system dependency is missing or incompatible.
    #[error("{message}")]
    Setup {
        message: String,
        /// The dependency that caused the failure.
        dependency: String,
    },

    /// A filesystem operation failed. Permission or access problems (e.g. the
    /// config directory is not writable) are a common cause, but the
    /// underlying failure may be any OS errno condition (e.g. the disk is
    /// full). Inspect `code` for the specific errno when one is available.
    #[error("{message}")]
    Filesystem {
        message: String,
        /// The absolute path that caused the error.
        path: String,
        /// The file operation that was being attempted, e.g. `"read"` or
        /// `"write"`. Despite the field name, this does not imply the
        /// failure was itself a permission problem — it names the attempted
        /// operation regardless of the underlying errno, which may be a
        /// non-permission code.
        permission: String,
        /// The underlying OS errno code (e.g. `"ENOENT"`, `"EACCES"`), when
        /// the host platform was able to supply one. `None` when the host
        /// does not expose a machine-readable code.
        code: Option<String>,
    },

    /// A key rotation was requested while a previous rotation is still in its grace period.
    #[error("{message}")]
    RotationInProgress { message: String },

    /// Generic vault error for cases that don't fit a specific variant.
    #[error("{0}")]
    Other(String),
}

/// Why an executable-trust choice was rejected by `setup()`.
///
/// A dedicated enum keeps the discriminator invariant compile-time enforced in
/// the Rust core; it is converted to its kebab-case string form (via
/// [`ExecutableTrustRequiredReason::as_str`]) only at the WASM boundary, where
/// the TypeScript SDK reconstructs the matching `ExecutableTrustRequiredError.reason`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutableTrustRequiredReason {
    /// Neither an executable path nor an explicit skip was provided. An
    /// empty or whitespace-only executable path also counts as missing.
    MissingChoice,
    /// Both an executable path and an explicit skip were provided — mutually
    /// exclusive intents.
    ConflictingChoice,
    /// The retired literal `"dev"` opt-out sentinel was passed as the executable
    /// path; it is no longer supported and must be replaced with an explicit skip.
    LegacyDevSentinel,
}

impl ExecutableTrustRequiredReason {
    /// The stable kebab-case discriminator carried across the WASM/TS boundary.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingChoice => "missing-choice",
            Self::ConflictingChoice => "conflicting-choice",
            Self::LegacyDevSentinel => "legacy-dev-sentinel",
        }
    }
}
