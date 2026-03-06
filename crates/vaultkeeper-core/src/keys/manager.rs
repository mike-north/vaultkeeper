//! KeyManager — handles key generation, rotation, and lookup.

use super::types::{KeyMaterial, KeyState};
use crate::errors::VaultError;
use crate::util::time;
use std::sync::atomic::{AtomicU64, Ordering};

/// Monotonic counter to ensure unique key IDs even within the same millisecond.
static KEY_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Manages encryption keys and rotation lifecycle.
pub struct KeyManager {
    state: Option<KeyState>,
}

impl KeyManager {
    /// Create a new uninitialized KeyManager.
    pub fn new() -> Self {
        Self { state: None }
    }

    /// Initialize the key manager, generating a fresh key.
    pub fn init(&mut self) -> Result<(), VaultError> {
        let key = Self::generate_key()?;
        self.state = Some(KeyState {
            current: key,
            previous: None,
        });
        Ok(())
    }

    /// Get the current (active) key.
    pub fn get_current_key(&self) -> Result<&KeyMaterial, VaultError> {
        self.state
            .as_ref()
            .map(|s| &s.current)
            .ok_or(VaultError::Other("KeyManager not initialized".to_string()))
    }

    /// Get the previous key (if in grace period).
    pub fn get_previous_key(&self) -> Option<&KeyMaterial> {
        self.state.as_ref().and_then(|s| s.previous.as_ref())
    }

    /// Find a key by its ID. Returns the key and whether it is the current key.
    pub fn find_key_by_id(&self, kid: &str) -> Option<(&KeyMaterial, bool)> {
        let state = self.state.as_ref()?;
        if state.current.id == kid {
            return Some((&state.current, true));
        }
        if let Some(ref prev) = state.previous
            && prev.id == kid
        {
            return Some((prev, false));
        }
        None
    }

    /// Rotate the current key. The old key becomes `previous` for the grace period.
    pub fn rotate_key(&mut self, _grace_period_ms: u64) -> Result<(), VaultError> {
        let state = self
            .state
            .as_mut()
            .ok_or(VaultError::Other("KeyManager not initialized".to_string()))?;

        if state.previous.is_some() {
            return Err(VaultError::RotationInProgress {
                message: "A key rotation is already in progress".to_string(),
            });
        }

        let new_key = Self::generate_key()?;
        let old_current = std::mem::replace(&mut state.current, new_key);
        state.previous = Some(old_current);

        Ok(())
    }

    /// Emergency key revocation — removes the previous key immediately.
    pub fn revoke_key(&mut self) -> Result<(), VaultError> {
        let state = self
            .state
            .as_mut()
            .ok_or(VaultError::Other("KeyManager not initialized".to_string()))?;
        state.previous = None;

        // Generate a new current key
        let new_key = Self::generate_key()?;
        state.current = new_key;

        Ok(())
    }

    /// Generate a new 32-byte key with a unique ID.
    fn generate_key() -> Result<KeyMaterial, VaultError> {
        let mut key_bytes = vec![0u8; 32];
        getrandom::fill(&mut key_bytes).map_err(|e| VaultError::Other(e.to_string()))?;

        let ts = time::now_millis();
        let seq = KEY_COUNTER.fetch_add(1, Ordering::Relaxed);
        let id = format!("k-{ts}-{seq}");

        Ok(KeyMaterial {
            id,
            key: key_bytes,
            created_at: time::now_secs(),
        })
    }
}

impl Default for KeyManager {
    fn default() -> Self {
        Self::new()
    }
}
