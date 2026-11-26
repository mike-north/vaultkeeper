//! Key management types.

use std::collections::HashMap;

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

// ---------------------------------------------------------------------------
// Lease revocation state (issue #298)
// ---------------------------------------------------------------------------

/// A single revoked lease entry: the token's `jti` and its own `exp`, so a
/// once-swept entry can never outlive the token it revokes — bounded growth
/// by construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JtiEntry {
    /// The revoked token's `jti` claim.
    pub jti: String,
    /// The revoked token's own `exp` claim (Unix seconds). Used only to
    /// decide when this entry can be swept — never compared against "now"
    /// for anything else.
    pub exp: u64,
}

/// Persistent, tamper-evident, two-axis lease revocation state (issue #298).
///
/// Lives inside the same encrypted `keys.enc` envelope
/// [`super::storage`] already persists the vault encryption key state in —
/// see that module's docs for why co-location gives this authentication, an
/// anti-rollback anchor, and atomic writes with no new trust root.
///
/// - `rev_state_gen` is a monotonic counter bumped on every mutation. A
///   validator tracks the highest generation it has itself observed and
///   rejects any load reporting a lower one — see
///   [`super::storage::load_revocation_for_validation`] — detecting a
///   restored, validly-sealed-but-stale copy of the store (a rollback/replay
///   attack; a signature/GCM tag alone cannot catch this, since the restored
///   copy's tag is genuine).
/// - `jti` holds one entry per explicitly revoked token. Validation rejects
///   any lease whose `jti` appears here.
/// - `key_generations` maps a signing key's name (matches
///   [`crate::types::VaultClaims::sub`]) to the generation it is currently
///   on. Validation rejects any lease whose `kgen` claim is below the
///   recorded generation for its `sub`.
///
/// **`key_generations` is never swept or removed** — even when the
/// underlying signing key is deleted and re-enrolled under the same name.
/// Removing an entry would let a re-created key reset to generation 0 and
/// silently revive every lease revoked under the old generation (the same
/// failure shape as issue #285's FIFO-eviction gap, applied to the per-key
/// axis instead of the per-jti one). Growth is bounded by the number of
/// signing keys ever created, which is operator-controlled and small — unlike
/// `jti`, there is no exp-driven ceiling to apply here, and none is needed.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RevocationState {
    /// Monotonic anti-rollback counter, bumped on every mutation.
    pub rev_state_gen: u64,
    /// Per-token revocations, swept once past their own `exp`.
    pub jti: Vec<JtiEntry>,
    /// Per-key generation, keyed by [`crate::types::VaultClaims::sub`].
    /// Never swept or removed.
    pub key_generations: HashMap<String, u64>,
}

impl RevocationState {
    /// Revoke a single lease by `jti`, recording its own `exp` so it can
    /// later be swept. Idempotent on the entry itself (a repeated `jti` is
    /// not duplicated) but always bumps `rev_state_gen`, so a repeated revoke
    /// remains observable to anyone tracking the generation.
    pub fn revoke_jti(&mut self, jti: impl Into<String>, exp: u64) {
        let jti = jti.into();
        if !self.jti.iter().any(|entry| entry.jti == jti) {
            self.jti.push(JtiEntry { jti, exp });
        }
        self.rev_state_gen += 1;
    }

    /// Revoke every outstanding lease for `key_name` by incrementing its
    /// generation — a single operation that invalidates every lease minted
    /// under a lower generation, without enumerating them.
    pub fn revoke_key(&mut self, key_name: impl Into<String>) {
        let entry = self.key_generations.entry(key_name.into()).or_insert(0);
        *entry += 1;
        self.rev_state_gen += 1;
    }

    /// Drop every `jti` entry whose own `exp` has already passed `now_secs`.
    /// Returns the number of entries removed. `key_generations` is
    /// deliberately never touched here — see the type doc for why sweeping
    /// it would be a revocation bypass.
    pub fn sweep_expired(&mut self, now_secs: u64) -> usize {
        let before = self.jti.len();
        self.jti.retain(|entry| entry.exp > now_secs);
        before - self.jti.len()
    }

    /// Whether `jti` has been explicitly revoked.
    #[must_use]
    pub fn is_jti_revoked(&self, jti: &str) -> bool {
        self.jti.iter().any(|entry| entry.jti == jti)
    }

    /// The minimum generation a lease for `key_name` must carry to still be
    /// valid. `0` when the key has never been revoked.
    #[must_use]
    pub fn min_generation_for(&self, key_name: &str) -> u64 {
        self.key_generations.get(key_name).copied().unwrap_or(0)
    }
}
