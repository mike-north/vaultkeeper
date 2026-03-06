//! JWE token creation, decryption, and blocklist.
//!
//! Implements compact JWE (RFC 7516) with `dir` algorithm + `A256GCM`.
//! Wire-compatible with the `jose` npm library used by the TypeScript implementation.

mod token;
mod types;

pub use token::{
    block_token, clear_blocklist, create_token, decrypt_token, extract_kid, is_blocked,
    validate_claims, CreateTokenOptions,
};
pub use types::VaultJweHeader;
