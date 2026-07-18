//! Key management types.

/// A cryptographic key with metadata.
#[derive(Debug, Clone)]
pub struct KeyMaterial {
    /// Unique identifier, format: `k-{millis}-{seq}` where `millis` is the
    /// generation timestamp and `seq` is a monotonic counter for uniqueness.
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
    /// When the last rotation occurred (milliseconds since Unix epoch).
    /// Used for lazy grace period enforcement.
    pub rotated_at_ms: Option<u128>,
    /// Grace period duration in milliseconds.
    pub grace_period_ms: Option<u64>,
}

/// Configuration for key rotation behavior.
#[derive(Debug, Clone)]
pub struct KeyRotationConfig {
    /// How long (in milliseconds) the previous key remains valid after rotation.
    pub grace_period_ms: u64,
}

/// A point-in-time snapshot of [`KeyManager`](super::KeyManager) state,
/// suitable for persisting across processes via `keys::storage`. Produced by
/// [`KeyManager::snapshot`](super::KeyManager::snapshot) and consumed by
/// [`KeyManager::hydrate`](super::KeyManager::hydrate).
///
/// The rotation grace period is represented purely as an absolute expiry
/// timestamp (epoch milliseconds); whether a rotation is "in progress" is
/// derived by comparing it to the current time, so the guard survives
/// process restarts without a live timer. Mirrors the TypeScript
/// `KeyStateSnapshot` (`packages/vaultkeeper/src/keys/types.ts`).
#[derive(Debug, Clone)]
pub struct KeyStateSnapshot {
    /// The currently active encryption key.
    pub current: KeyMaterial,
    /// The previous key, present only while its grace period is still active.
    pub previous: Option<KeyMaterial>,
    /// Absolute epoch-millisecond time at which the current grace period
    /// ends. Present only while a rotation grace period is active.
    pub grace_period_expires_at_ms: Option<u64>,
}
