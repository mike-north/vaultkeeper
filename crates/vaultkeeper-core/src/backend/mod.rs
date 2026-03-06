//! Backend abstraction layer for vaultkeeper.
//!
//! All backends implement [`SecretBackend`]. OS-specific backends delegate
//! system calls through [`HostPlatform`].

pub mod file;
pub mod in_memory;
mod registry;
mod types;

pub use file::FileBackend;
pub use in_memory::InMemoryBackend;
pub use registry::BackendRegistry;
pub use types::{ExecOutput, HostPlatform, ListableBackend, Platform, SecretBackend};
