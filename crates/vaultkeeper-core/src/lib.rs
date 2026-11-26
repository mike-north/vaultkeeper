//! vaultkeeper-core: unified, policy-enforced secret storage.
//!
//! This crate contains all business logic for vaultkeeper. It is platform-agnostic —
//! OS interactions go through the [`HostPlatform`] trait injected by the caller.

pub mod access;
pub mod backend;
pub mod config;
pub mod doctor;
pub mod errors;
pub mod identity;
pub mod jwe;
pub mod keys;
pub mod profile;
pub mod resolve;
pub mod run;
pub mod signing;
pub mod types;
pub(crate) mod util;
pub mod vault;

// Re-export key public types at crate root for convenience.
pub use backend::{
    BackendCapabilities, InMemoryBackend, PresenceCapableBackend, PresenceOperation,
    get_backend_capabilities, is_presence_capable_backend,
};
pub use errors::{ExecutableTrustRequiredReason, VaultError};
pub use identity::{HANDLE_TABLE_MAX_SIZE, HandleId, HandleTable, StoredClaims};
pub use resolve::{ResolveOptions, ResolvedEnv, resolve_profile};
pub use run::{
    FILE_ONLY_DEGRADATION_NOTICE, RunPlan, SetEntry, apply_set_overlay,
    file_only_degradation_applies, parse_set_flag, render_dry_run,
};
pub use types::{
    BackendConfig, ClaimsKind, ExecRequest, ExecResult, FetchRequest, KeyStatus, LeasePresence,
    PreflightCheck, PreflightCheckStatus, PreflightResult, ScopedPreflightCheck, SecretAccessor,
    SigningAlgorithm, SigningClaims, SigningPublicKey, TrustTier, VaultClaims, VaultConfig,
    VaultResponse, VerifyRequest,
};
pub use vault::{VaultKeeper, enforce_presence_requirement};
