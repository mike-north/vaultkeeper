//! Backend abstraction layer for vaultkeeper.
//!
//! All backends implement [`SecretBackend`]. OS-specific backends delegate
//! system calls through [`HostPlatform`].

pub mod in_memory;
mod registry;
mod types;

pub use in_memory::InMemoryBackend;
pub use registry::BackendRegistry;
pub use types::{ExecOutput, HostPlatform, ListableBackend, Platform, SecretBackend};
