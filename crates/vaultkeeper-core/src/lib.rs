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
pub mod types;
pub(crate) mod util;
pub mod vault;

// Re-export key public types at crate root for convenience.
pub use errors::VaultError;
pub use types::{
    BackendConfig, ExecRequest, ExecResult, FetchRequest, KeyStatus, PreflightCheck,
    PreflightCheckStatus, PreflightResult, SecretAccessor, SignRequest, SignResult, TrustTier,
    VaultClaims, VaultConfig, VaultResponse, VerifyRequest,
};
pub use backend::InMemoryBackend;
pub use vault::VaultKeeper;
