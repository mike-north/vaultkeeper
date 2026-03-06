//! Executable hashing utilities.

use crate::backend::HostPlatform;
use crate::errors::VaultError;
use sha2::{Digest, Sha256};
use std::fmt::Write;
use std::path::Path;

/// Compute the SHA-256 hex digest of the file at `path` using the
/// given [`HostPlatform`] for file I/O.
pub async fn hash_executable(
    host: &dyn HostPlatform,
    path: &Path,
) -> Result<String, VaultError> {
    let content = host.read_file(path).await?;
    Ok(sha256_hex(&content))
}

/// Compute the SHA-256 hex digest of raw bytes.
pub fn hash_bytes(data: &[u8]) -> String {
    sha256_hex(data)
}

fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    let mut hex = String::with_capacity(64);
    for byte in digest {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_bytes_produces_hex_sha256() {
        // echo -n "hello" | sha256sum
        let hash = hash_bytes(b"hello");
        assert_eq!(
            hash,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn hash_empty_input() {
        // echo -n "" | sha256sum
        let hash = hash_bytes(b"");
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
