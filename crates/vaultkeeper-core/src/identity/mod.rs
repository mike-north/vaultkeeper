//! Executable identity verification, TOFU manifest, and session tokens.

pub mod handles;
pub mod hash;
pub mod manifest;
pub mod trust;
mod types;

pub use handles::{HANDLE_TABLE_MAX_SIZE, HandleId, HandleTable, StoredClaims};
pub use types::{
    IdentityInfo, TrustManifest, TrustManifestEntry, TrustOptions, TrustVerificationResult,
};
