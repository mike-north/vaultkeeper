//! Key management and rotation logic.

mod manager;
pub mod storage;
mod types;

pub use manager::KeyManager;
pub use storage::{load_key_state, save_key_state};
pub use types::{KeyMaterial, KeyRotationConfig, KeyState, KeyStateSnapshot};
