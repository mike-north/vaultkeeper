//! Key management and rotation logic.

mod manager;
pub mod storage;
mod types;

pub use manager::KeyManager;
pub use storage::{
    load_key_state, load_revocation_for_validation, mutate_revocation_state, save_key_state,
};
pub use types::{
    JtiEntry, KeyMaterial, KeyRotationConfig, KeyState, KeyStateSnapshot, RevocationState,
};
