//! Detached-payload Compact JWS signing stack (Ed25519 / EdDSA).
//!
//! Wire-compatible with the TypeScript reference implementation
//! (`packages/vaultkeeper/src/access/jws.ts`): RFC 7515 §7.2.2 detached
//! Compact JWS + RFC 7797 (`b64:false`) unencoded payload option, `alg:
//! EdDSA` (Ed25519) only.
//!
//! - [`ed25519`] holds the raw key-parsing and signature primitives.
//! - [`jws`] holds the pure JWS assembly/verification logic; it never parses
//!   or holds private key material — signing is delegated to a caller's
//!   [`crate::backend::SigningBackend`].

pub mod ed25519;
mod jws;

pub use jws::{JWS_ALG, create_detached_jws, verify_detached_jws};
