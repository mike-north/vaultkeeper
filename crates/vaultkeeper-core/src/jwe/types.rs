//! JWE-specific types for the vaultkeeper token layer.

use serde::{Deserialize, Serialize};

/// JWE protected header parameters used for vaultkeeper tokens.
///
/// Uses `dir` (direct key agreement) + `A256GCM` with an optional `kid` for key rotation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultJweHeader {
    /// Key Agreement algorithm — always `"dir"`.
    pub alg: String,
    /// Content Encryption algorithm — always `"A256GCM"`.
    pub enc: String,
    /// Key ID for rotation tracking.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
}

impl Default for VaultJweHeader {
    fn default() -> Self {
        Self {
            alg: "dir".to_string(),
            enc: "A256GCM".to_string(),
            kid: None,
        }
    }
}
