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

    /// A filesystem operation failed due to permissions.
    #[error("{message}")]
    Filesystem {
        message: String,
        /// The absolute path that caused the error.
        path: String,
        /// The required permission level (e.g. `"read"`, `"write"`).
        permission: String,
    },

    /// A key rotation was requested while a previous rotation is still in its grace period.
    #[error("{message}")]
    RotationInProgress { message: String },

    /// Generic vault error for cases that don't fit a specific variant.
    #[error("{0}")]
    Other(String),
}
