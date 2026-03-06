//! Key management and rotation logic.

mod manager;
mod types;

pub use manager::KeyManager;
pub use types::{KeyMaterial, KeyRotationConfig, KeyState};
