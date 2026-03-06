//! Access patterns: delegated fetch/exec, controlled-direct access, signing.
//!
//! All access patterns substitute `{{secret}}` placeholders with the actual
//! secret value. The raw secret never appears in return values.
//!
//! Core types:
//! - [`SecretAccessor`] — one-time-read wrapper that zeroes the secret after access.
//!   Defined in [`crate::types`] and re-exported from the crate root.
//! - The CLI `exec` command handles delegated exec (injecting secret as env var).
//!
//! Higher-level patterns (delegated-fetch, delegated-sign, delegated-verify) are
//! implemented in the TypeScript SDK layer on top of the WASM core.

pub use crate::types::SecretAccessor;
