//! Backend abstraction layer for vaultkeeper.
//!
//! All backends implement [`SecretBackend`]. OS-specific backends delegate
//! system calls through [`HostPlatform`].

pub mod file;
pub mod in_memory;
mod registry;
pub mod secret_tool;
mod signing_store;
mod types;

pub use file::FileBackend;
pub use in_memory::InMemoryBackend;
pub use registry::BackendRegistry;
pub use secret_tool::SecretToolBackend;
pub use types::{
    ApprovalContext, BackendCapabilities, ExecOptions, ExecOutput, HostPlatform, HttpRequest,
    HttpResponse, ListableBackend, Platform, PresenceCapableBackend, PresenceOperation,
    SecretBackend, SigningBackend, get_backend_capabilities, is_presence_capable_backend,
};
