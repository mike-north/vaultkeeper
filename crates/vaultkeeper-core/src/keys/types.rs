//! Key management types.

/// A cryptographic key with metadata.
#[derive(Debug, Clone)]
pub struct KeyMaterial {
    /// Unique identifier, format: `k-{timestamp}`.
    pub id: String,
    /// 32-byte raw key material.
    pub key: Vec<u8>,
    /// When the key was generated (seconds since Unix epoch).
    pub created_at: u64,
}

impl Drop for KeyMaterial {
    fn drop(&mut self) {
        // Zero the key material on drop.
        self.key.iter_mut().for_each(|b| *b = 0);
    }
}

/// The active state of the key pair (current + optional previous in grace period).
#[derive(Debug)]
pub struct KeyState {
    /// The currently active key for encryption.
    pub current: KeyMaterial,
    /// The previous key, only present during a grace period.
    pub previous: Option<KeyMaterial>,
}

/// Configuration for key rotation behavior.
#[derive(Debug, Clone)]
pub struct KeyRotationConfig {
    /// How long (in milliseconds) the previous key remains valid after rotation.
    pub grace_period_ms: u64,
}
