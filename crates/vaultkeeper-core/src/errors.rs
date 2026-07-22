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

    // --- Access Pattern Failures ---
    /// An operation requires a backend capability (e.g. presence-per-use) that
    /// the active backend cannot provide.
    #[error("{message}")]
    NotCapable {
        message: String,
        /// The `type` identifier of the active backend that lacked the capability.
        backend_type: String,
        /// The machine-readable capability key that was required but not advertised.
        capability: String,
    },

    /// A required fresh, per-use human presence action was explicitly declined.
    #[error("{message}")]
    PresenceDeclined {
        message: String,
        /// The `type` identifier of the backend that requested the presence action.
        backend_type: String,
    },

    /// A required fresh, per-use human presence action did not happen within
    /// the allotted time.
    #[error("{message}")]
    PresenceTimeout {
        message: String,
        /// The `type` identifier of the backend that requested the presence action.
        backend_type: String,
        /// How long (in milliseconds) the operation waited for the presence action.
        timeout_ms: u64,
    },

    /// Signing-key material could not be parsed — corrupt or tampered key
    /// material, or a structurally invalid public key supplied for verification.
    #[error("{message}")]
    InvalidKeyMaterial { message: String },

    /// A named signing key does not exist in the active backend.
    #[error("{message}")]
    SigningKeyNotFound {
        message: String,
        /// The signing-key name that was requested.
        id: String,
    },

    /// A signing key enrollment was attempted under a name that already exists.
    #[error("{message}")]
    SigningKeyAlreadyExists {
        message: String,
        /// The signing-key name that already exists.
        id: String,
    },

    /// A signing operation was requested against a backend that does not
    /// implement the signing contract.
    #[error("{message}")]
    SigningNotSupported {
        message: String,
        /// The type identifier of the active backend that cannot sign.
        backend_type: String,
        /// The built-in backend type identifiers known to implement the signing contract.
        built_in_signing_backends: Vec<String>,
    },

    /// Spawning or running a subprocess failed.
    #[error("{message}")]
    Exec {
        message: String,
        /// The command that failed to execute.
        command: String,
    },

    /// A delegated `fetch()` call failed before a `Response` could be produced.
    #[error("{message}")]
    Fetch {
        message: String,
        /// The unresolved URL template that fetch failed to request.
        url: String,
    },

    /// A JWE string is invalid or cannot be processed — structurally
    /// malformed, decryption failure, or a decrypted payload that does not
    /// match the expected claims schema.
    #[error("{message}")]
    InvalidToken { message: String },

    /// A one-time secret accessor was read after it had already been consumed.
    #[error("{message}")]
    AccessorConsumed { message: String },

    // --- Config Validation Failures ---
    /// A config value failed structural or semantic validation.
    #[error("{message}")]
    ConfigValidation {
        message: String,
        /// The dotted/bracketed path to the offending config field.
        field: String,
        /// The path of the config file that failed validation, when the error
        /// originated from loading a file on disk rather than validating an
        /// in-memory value directly.
        config_file_path: Option<String>,
    },

    /// A config's `backends[].type` names a backend that is not registered.
    ///
    /// A specialization of [`VaultError::ConfigValidation`]: an unknown
    /// backend type is a semantic schema failure, so it fails config
    /// validation the same way a malformed config field does.
    #[error("{message}")]
    UnknownBackendType {
        message: String,
        /// The dotted/bracketed path to the offending config field.
        field: String,
        /// The unregistered backend type named in the config.
        backend_type: String,
        /// The backend type identifiers that were registered when validation ran.
        known_backend_types: Vec<String>,
        /// The path of the config file that failed validation, when known.
        config_file_path: Option<String>,
    },

    /// A config file's contents could not be parsed as JSON.
    #[error("{message}")]
    ConfigParse {
        message: String,
        /// The path of the config file that failed to parse.
        path: String,
        /// The 1-based line number of the parse failure, when the underlying
        /// parser exposed one.
        line: Option<u32>,
        /// The 1-based column number of the parse failure, when the
        /// underlying parser exposed one.
        column: Option<u32>,
    },

    // --- Environment Profile Failures (issue #277) ---
    /// A profile requested a materialization the current implementation
    /// does not support. Two request shapes produce this error:
    ///
    /// 1. The `materialize` field used the reserved object form
    ///    (`{ "mode": "...", ... }`). The object form is polymorphic by
    ///    design but v1 only implements the plain string values (`"secret"`
    ///    | `"lease"`) — every object-form `mode` is refused with this typed
    ///    error rather than a generic parse failure, so the reservation is
    ///    discoverable and a real v2 implementation can be non-breaking
    ///    later. `mode` carries the reserved mode name (e.g. `"reference"`).
    /// 2. A materialization *combination* the resolver cannot yet satisfy,
    ///    refused at resolve time. `mode` then carries a stable kebab-case
    ///    slug naming the unsupported request — currently
    ///    `"signing-key-lease"` (session signing leases, pending the epic's
    ///    session-mint work) and `"secret-lease-presence-at-mint"`
    ///    (`requirePresenceAtMint` on a secret-backed lease; no
    ///    `HostPlatform` exists at resolve time to prompt with). These slugs
    ///    are a documented, stable contract for programmatic callers.
    #[error("{message}")]
    MaterializeModeUnsupported {
        message: String,
        /// The reserved `mode` name or unsupported-request slug — see the
        /// variant docs for the enumerated values.
        mode: String,
    },

    /// Generic vault error for cases that don't fit a specific variant.
    #[error("{0}")]
    Other(String),
}

impl VaultError {
    /// Fill in the on-disk path a load failure originated from, when the
    /// error was built without knowing it (e.g. a loader that parses/
    /// validates from an in-memory string and only learns the real path at
    /// its caller). A no-op for every other variant.
    ///
    /// Only ever *sets* the path — never overwrites one a variant already
    /// carries — so a caller can apply this unconditionally after any
    /// fallible load without clobbering a more specific path an inner layer
    /// already attached.
    #[must_use]
    pub fn with_config_file_path(self, path: impl Into<String>) -> Self {
        match self {
            VaultError::ConfigParse {
                message,
                path: existing_path,
                line,
                column,
            } if existing_path.is_empty() => VaultError::ConfigParse {
                message,
                path: path.into(),
                line,
                column,
            },
            VaultError::ConfigValidation {
                message,
                field,
                config_file_path: None,
            } => VaultError::ConfigValidation {
                message,
                field,
                config_file_path: Some(path.into()),
            },
            other => other,
        }
    }
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

// --- WASM boundary taxonomy ---
//
// The three items below (`ALL_ERROR_CODES`, `vault_error_code`,
// `vault_error_fields`) are the single source of truth for the error
// taxonomy that crosses the WASM boundary. They live here — in the
// platform-agnostic core, not the wasm32-only `vaultkeeper-wasm` crate —
// specifically so they are unit-testable with a plain `cargo test` and no
// wasm32 target. `crates/vaultkeeper-wasm/src/wasm_impl.rs` calls these
// directly; its own `vault_error_to_js` is a thin JSON-serialization wrapper
// around `vault_error_fields`.

/// Canonical list of every machine-readable error code that can cross the
/// WASM boundary.
///
/// [`vault_error_code`]'s exhaustive match (no wildcard arm) guarantees every
/// [`VaultError`] variant maps to one of these codes at compile time. Drift
/// between this list and the TypeScript reconstruction map in
/// `packages/vaultkeeper-wasm/src/errors.ts` is caught in both directions by:
/// - `crates/vaultkeeper-core/tests/error_taxonomy.rs` (Rust side — asserts
///   every code here is produced by some variant, and every variant's code is
///   in this list)
/// - `packages/vaultkeeper-wasm/src/test/error-parity.test.ts` (TS side —
///   fetches this exact list from the compiled WASM binary via the exported
///   `allVaultErrorCodes()` and asserts it equals the TS reconstruction map's
///   known codes exactly)
pub const ALL_ERROR_CODES: &[&str] = &[
    "secret-not-found",
    "decryption",
    "token-expired",
    "key-rotated",
    "key-revoked",
    "token-revoked",
    "usage-limit-exceeded",
    "rotation-in-progress",
    "backend-locked",
    "device-not-present",
    "authorization-denied",
    "backend-unavailable",
    "plugin-not-found",
    "identity-mismatch",
    "executable-trust-required",
    "invalid-algorithm",
    "setup",
    "filesystem",
    "not-capable",
    "presence-declined",
    "presence-timeout",
    "invalid-key-material",
    "signing-key-not-found",
    "signing-key-already-exists",
    "signing-not-supported",
    "exec",
    "fetch",
    "invalid-token",
    "accessor-consumed",
    "config-validation",
    "unknown-backend-type",
    "config-parse",
    "materialize-mode-unsupported",
    "vault-error",
];

/// Stable machine-readable code for a [`VaultError`], used by the TypeScript
/// bridge to reconstruct a typed error instance from the thrown value.
///
/// Typed variants map one-to-one to a code from [`ALL_ERROR_CODES`].
/// `VaultError::Other(..)` — used for the remaining malformed/validation
/// failures that don't yet have a dedicated variant — maps to the generic
/// `vault-error`.
#[must_use]
pub fn vault_error_code(e: &VaultError) -> &'static str {
    match e {
        VaultError::SecretNotFound { .. } => "secret-not-found",
        VaultError::Decryption { .. } => "decryption",
        VaultError::TokenExpired { .. } => "token-expired",
        VaultError::KeyRotated { .. } => "key-rotated",
        VaultError::KeyRevoked { .. } => "key-revoked",
        VaultError::TokenRevoked { .. } => "token-revoked",
        VaultError::UsageLimitExceeded { .. } => "usage-limit-exceeded",
        VaultError::RotationInProgress { .. } => "rotation-in-progress",
        VaultError::BackendLocked { .. } => "backend-locked",
        VaultError::DeviceNotPresent { .. } => "device-not-present",
        VaultError::AuthorizationDenied { .. } => "authorization-denied",
        VaultError::BackendUnavailable { .. } => "backend-unavailable",
        VaultError::PluginNotFound { .. } => "plugin-not-found",
        VaultError::IdentityMismatch { .. } => "identity-mismatch",
        VaultError::ExecutableTrustRequired { .. } => "executable-trust-required",
        VaultError::InvalidAlgorithm { .. } => "invalid-algorithm",
        VaultError::Setup { .. } => "setup",
        VaultError::Filesystem { .. } => "filesystem",
        VaultError::NotCapable { .. } => "not-capable",
        VaultError::PresenceDeclined { .. } => "presence-declined",
        VaultError::PresenceTimeout { .. } => "presence-timeout",
        VaultError::InvalidKeyMaterial { .. } => "invalid-key-material",
        VaultError::SigningKeyNotFound { .. } => "signing-key-not-found",
        VaultError::SigningKeyAlreadyExists { .. } => "signing-key-already-exists",
        VaultError::SigningNotSupported { .. } => "signing-not-supported",
        VaultError::Exec { .. } => "exec",
        VaultError::Fetch { .. } => "fetch",
        VaultError::InvalidToken { .. } => "invalid-token",
        VaultError::AccessorConsumed { .. } => "accessor-consumed",
        VaultError::ConfigValidation { .. } => "config-validation",
        VaultError::UnknownBackendType { .. } => "unknown-backend-type",
        VaultError::ConfigParse { .. } => "config-parse",
        VaultError::MaterializeModeUnsupported { .. } => "materialize-mode-unsupported",
        VaultError::Other(_) => "vault-error",
    }
}

/// JS `number` represents integers exactly only up to 2^53 - 1. A
/// `timeout_ms` beyond that is inherently lossy across the bridge, and the TS
/// reconstruction helper (`optionalNumber` in
/// `packages/vaultkeeper-wasm/src/errors.ts`) rejects unsafe integers and
/// falls back to the class default. Emitting the field only when it survives
/// the crossing exactly makes that an explicit boundary contract rather than
/// a silent rejection on the far side.
const JS_MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// The structured, JS-camelCase context fields carried by a [`VaultError`]
/// across the WASM boundary — everything `vault_error_to_js`
/// (`crates/vaultkeeper-wasm/src/wasm_impl.rs`) sets on the thrown object
/// besides `vaultErrorCode` and `message`.
///
/// Field keys are the exact camelCase names the TypeScript reconstruction map
/// (`packages/vaultkeeper-wasm/src/errors.ts`) expects. This is the real
/// "business logic" of the bridge; keeping it here (rather than inline in the
/// wasm32-only `wasm_impl.rs`) makes it unit-testable with a plain `cargo
/// test`.
#[must_use]
pub fn vault_error_fields(e: &VaultError) -> serde_json::Map<String, serde_json::Value> {
    let mut fields = serde_json::Map::new();
    match e {
        VaultError::TokenExpired { can_refresh, .. } => {
            fields.insert("canRefresh".into(), (*can_refresh).into());
        }
        VaultError::Decryption { path, .. } => {
            fields.insert("path".into(), path.clone().into());
        }
        VaultError::BackendLocked { interactive, .. } => {
            fields.insert("interactive".into(), (*interactive).into());
        }
        // The guard means an out-of-range timeout falls through to the
        // field-less catch-all — exactly the intended omission.
        VaultError::DeviceNotPresent { timeout_ms, .. } if *timeout_ms <= JS_MAX_SAFE_INTEGER => {
            fields.insert("timeoutMs".into(), (*timeout_ms).into());
        }
        VaultError::BackendUnavailable {
            reason, attempted, ..
        } => {
            fields.insert("reason".into(), reason.clone().into());
            fields.insert("attempted".into(), attempted.clone().into());
        }
        VaultError::PluginNotFound {
            plugin,
            install_url,
            ..
        } => {
            fields.insert("plugin".into(), plugin.clone().into());
            fields.insert("installUrl".into(), install_url.clone().into());
        }
        VaultError::IdentityMismatch {
            previous_hash,
            current_hash,
            ..
        } => {
            fields.insert("previousHash".into(), previous_hash.clone().into());
            fields.insert("currentHash".into(), current_hash.clone().into());
        }
        VaultError::ExecutableTrustRequired { reason, .. } => {
            fields.insert("reason".into(), reason.as_str().into());
        }
        VaultError::InvalidAlgorithm {
            algorithm, allowed, ..
        } => {
            fields.insert("algorithm".into(), algorithm.clone().into());
            fields.insert("allowed".into(), allowed.clone().into());
        }
        VaultError::Setup { dependency, .. } => {
            fields.insert("dependency".into(), dependency.clone().into());
        }
        VaultError::Filesystem {
            path,
            permission,
            code,
            ..
        } => {
            fields.insert("path".into(), path.clone().into());
            fields.insert("permission".into(), permission.clone().into());
            if let Some(code) = code {
                fields.insert("code".into(), code.clone().into());
            }
        }
        VaultError::NotCapable {
            backend_type,
            capability,
            ..
        } => {
            fields.insert("backendType".into(), backend_type.clone().into());
            fields.insert("capability".into(), capability.clone().into());
        }
        VaultError::PresenceDeclined { backend_type, .. } => {
            fields.insert("backendType".into(), backend_type.clone().into());
        }
        VaultError::PresenceTimeout {
            backend_type,
            timeout_ms,
            ..
        } => {
            fields.insert("backendType".into(), backend_type.clone().into());
            if *timeout_ms <= JS_MAX_SAFE_INTEGER {
                fields.insert("timeoutMs".into(), (*timeout_ms).into());
            }
        }
        VaultError::SigningKeyNotFound { id, .. }
        | VaultError::SigningKeyAlreadyExists { id, .. } => {
            fields.insert("keyName".into(), id.clone().into());
        }
        VaultError::SigningNotSupported {
            backend_type,
            built_in_signing_backends,
            ..
        } => {
            fields.insert("backendType".into(), backend_type.clone().into());
            fields.insert(
                "builtInSigningBackends".into(),
                built_in_signing_backends.clone().into(),
            );
        }
        VaultError::Exec { command, .. } => {
            fields.insert("command".into(), command.clone().into());
        }
        VaultError::Fetch { url, .. } => {
            fields.insert("url".into(), url.clone().into());
        }
        VaultError::ConfigValidation {
            field,
            config_file_path,
            ..
        } => {
            fields.insert("field".into(), field.clone().into());
            if let Some(p) = config_file_path {
                fields.insert("configFilePath".into(), p.clone().into());
            }
        }
        VaultError::UnknownBackendType {
            field,
            backend_type,
            known_backend_types,
            config_file_path,
            ..
        } => {
            fields.insert("field".into(), field.clone().into());
            fields.insert("backendType".into(), backend_type.clone().into());
            fields.insert("knownTypes".into(), known_backend_types.clone().into());
            if let Some(p) = config_file_path {
                fields.insert("configFilePath".into(), p.clone().into());
            }
        }
        VaultError::ConfigParse {
            path, line, column, ..
        } => {
            fields.insert("path".into(), path.clone().into());
            if let Some(line) = line {
                fields.insert("line".into(), (*line).into());
            }
            if let Some(column) = column {
                fields.insert("column".into(), (*column).into());
            }
        }
        VaultError::MaterializeModeUnsupported { mode, .. } => {
            fields.insert("mode".into(), mode.clone().into());
        }
        _ => {}
    }
    fields
}

/// One instance of every [`VaultError`] variant, populated with fixed,
/// distinguishable dummy field values — not real error conditions.
///
/// Exists purely to drive the cross-language error-taxonomy parity test:
/// `crates/vaultkeeper-core/tests/error_taxonomy.rs` uses it directly, and
/// the WASM diagnostic export `__testAllVaultErrors`
/// (`crates/vaultkeeper-wasm/src/wasm_impl.rs`) calls it to give
/// `packages/vaultkeeper-wasm/src/test/error-parity.test.ts` real
/// `vault_error_to_js`-produced values to reconstruct. Never called from a
/// real code path.
#[doc(hidden)]
#[must_use]
pub fn all_variants_for_parity_test() -> Vec<VaultError> {
    vec![
        VaultError::SecretNotFound {
            message: "secret not found".into(),
        },
        VaultError::Decryption {
            message: "decryption failed".into(),
            path: "/secrets/a.enc".into(),
        },
        VaultError::TokenExpired {
            message: "token expired".into(),
            can_refresh: true,
        },
        VaultError::KeyRotated {
            message: "key rotated".into(),
        },
        VaultError::KeyRevoked {
            message: "key revoked".into(),
        },
        VaultError::TokenRevoked {
            message: "token revoked".into(),
        },
        VaultError::UsageLimitExceeded {
            message: "usage limit exceeded".into(),
        },
        VaultError::RotationInProgress {
            message: "rotation in progress".into(),
        },
        VaultError::BackendLocked {
            message: "backend locked".into(),
            interactive: true,
        },
        VaultError::DeviceNotPresent {
            message: "device not present".into(),
            timeout_ms: 5000,
        },
        VaultError::AuthorizationDenied {
            message: "authorization denied".into(),
        },
        VaultError::BackendUnavailable {
            message: "backend unavailable".into(),
            reason: "all-failed".into(),
            attempted: vec!["keychain".into(), "file".into()],
        },
        VaultError::PluginNotFound {
            message: "plugin not found".into(),
            plugin: "vaultkeeper-1password".into(),
            install_url: "https://example.test/install".into(),
        },
        VaultError::IdentityMismatch {
            message: "identity mismatch".into(),
            previous_hash: "aaaa".into(),
            current_hash: "bbbb".into(),
        },
        VaultError::ExecutableTrustRequired {
            message: "executable trust required".into(),
            reason: ExecutableTrustRequiredReason::MissingChoice,
        },
        VaultError::InvalidAlgorithm {
            message: "invalid algorithm".into(),
            algorithm: "RS256".into(),
            allowed: vec!["EdDSA".into()],
        },
        VaultError::Setup {
            message: "setup failed".into(),
            dependency: "openssl".into(),
        },
        VaultError::Filesystem {
            message: "filesystem error".into(),
            path: "/config/config.json".into(),
            permission: "read".into(),
            code: Some("EACCES".into()),
        },
        VaultError::NotCapable {
            message: "not capable".into(),
            backend_type: "keychain".into(),
            capability: "presencePerUse".into(),
        },
        VaultError::PresenceDeclined {
            message: "presence declined".into(),
            backend_type: "yubikey".into(),
        },
        VaultError::PresenceTimeout {
            message: "presence timeout".into(),
            backend_type: "yubikey".into(),
            timeout_ms: 15000,
        },
        VaultError::InvalidKeyMaterial {
            message: "invalid key material".into(),
        },
        VaultError::SigningKeyNotFound {
            message: "signing key not found".into(),
            id: "release-key".into(),
        },
        VaultError::SigningKeyAlreadyExists {
            message: "signing key already exists".into(),
            id: "release-key".into(),
        },
        VaultError::SigningNotSupported {
            message: "signing not supported".into(),
            backend_type: "keychain".into(),
            built_in_signing_backends: vec!["file".into()],
        },
        VaultError::Exec {
            message: "exec failed".into(),
            command: "curl".into(),
        },
        VaultError::Fetch {
            message: "fetch failed".into(),
            url: "https://example.test/{{secret}}".into(),
        },
        VaultError::InvalidToken {
            message: "invalid token".into(),
        },
        VaultError::AccessorConsumed {
            message: "accessor consumed".into(),
        },
        VaultError::ConfigValidation {
            message: "config validation failed".into(),
            field: "backends[0].path".into(),
            config_file_path: Some("/config/config.json".into()),
        },
        VaultError::UnknownBackendType {
            message: "unknown backend type".into(),
            field: "backends[0].type".into(),
            backend_type: "made-up".into(),
            known_backend_types: vec!["file".into(), "keychain".into()],
            config_file_path: Some("/config/config.json".into()),
        },
        VaultError::ConfigParse {
            message: "config parse failed".into(),
            path: "/config/config.json".into(),
            line: Some(3),
            column: Some(12),
        },
        VaultError::MaterializeModeUnsupported {
            message: "materialize mode unsupported".into(),
            mode: "reference".into(),
        },
        VaultError::Other("generic vault error".into()),
    ]
}

#[cfg(test)]
mod with_config_file_path_tests {
    use super::VaultError;

    #[test]
    fn fills_in_config_parse_path_when_empty() {
        let err = VaultError::ConfigParse {
            message: "bad json".into(),
            path: String::new(),
            line: Some(1),
            column: Some(2),
        };
        let filled = err.with_config_file_path("/config/profiles/p.json");
        assert!(matches!(
            filled,
            VaultError::ConfigParse { path, .. } if path == "/config/profiles/p.json"
        ));
    }

    #[test]
    fn does_not_overwrite_an_existing_config_parse_path() {
        let err = VaultError::ConfigParse {
            message: "bad json".into(),
            path: "/already/set.json".into(),
            line: None,
            column: None,
        };
        let filled = err.with_config_file_path("/should/not/apply.json");
        assert!(matches!(
            filled,
            VaultError::ConfigParse { path, .. } if path == "/already/set.json"
        ));
    }

    #[test]
    fn fills_in_config_validation_file_path_when_absent() {
        let err = VaultError::ConfigValidation {
            message: "invalid".into(),
            field: "name".into(),
            config_file_path: None,
        };
        let filled = err.with_config_file_path("/config/profiles/p.json");
        assert!(matches!(
            filled,
            VaultError::ConfigValidation { config_file_path: Some(p), .. }
                if p == "/config/profiles/p.json"
        ));
    }

    #[test]
    fn does_not_overwrite_an_existing_config_validation_file_path() {
        let err = VaultError::ConfigValidation {
            message: "invalid".into(),
            field: "name".into(),
            config_file_path: Some("/already/set.json".into()),
        };
        let filled = err.with_config_file_path("/should/not/apply.json");
        assert!(matches!(
            filled,
            VaultError::ConfigValidation { config_file_path: Some(p), .. }
                if p == "/already/set.json"
        ));
    }

    #[test]
    fn is_a_no_op_for_other_variants() {
        let err = VaultError::Other("generic".into());
        let filled = err.with_config_file_path("/irrelevant.json");
        assert!(matches!(filled, VaultError::Other(m) if m == "generic"));
    }
}
