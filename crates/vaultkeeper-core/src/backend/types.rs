//! Backend trait definitions and host platform abstraction.

use crate::errors::VaultError;
use std::path::Path;

/// Output from a subprocess execution.
#[derive(Debug, Clone)]
pub struct ExecOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_code: i32,
}

/// Platform identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Darwin,
    Linux,
    Windows,
}

/// Host platform abstraction for OS interactions.
///
/// In native mode, implementations use `std::process::Command` and `std::fs`.
/// In WASM mode, implementations call back into JavaScript host functions.
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
pub trait HostPlatform: Send + Sync {
    /// Execute a subprocess, returning stdout, stderr, and exit code.
    async fn exec(
        &self,
        cmd: &str,
        args: &[&str],
        stdin: Option<&[u8]>,
    ) -> Result<ExecOutput, VaultError>;

    /// Read a file.
    async fn read_file(&self, path: &Path) -> Result<Vec<u8>, VaultError>;

    /// Write a file with the given Unix permission `mode` (e.g. `0o600`).
    /// On non-Unix platforms the mode hint may be ignored.
    async fn write_file(&self, path: &Path, content: &[u8], mode: u32) -> Result<(), VaultError>;

    /// Check if a file exists.
    async fn file_exists(&self, path: &Path) -> Result<bool, VaultError>;

    /// Get platform type.
    fn platform(&self) -> Platform;

    /// Get config directory.
    fn config_dir(&self) -> &Path;
}

/// Abstraction interface for all secret storage backends.
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
pub trait SecretBackend: Send + Sync {
    /// Unique type identifier for this backend.
    fn backend_type(&self) -> &str;

    /// Human-readable display name for this backend.
    fn display_name(&self) -> &str;

    /// Check whether this backend is available on the current system.
    async fn is_available(&self) -> bool;

    /// Store a secret under the given id.
    async fn store(&self, id: &str, secret: &str) -> Result<(), VaultError>;

    /// Retrieve a secret by id.
    async fn retrieve(&self, id: &str) -> Result<String, VaultError>;

    /// Delete a secret by id.
    async fn delete(&self, id: &str) -> Result<(), VaultError>;

    /// Check whether a secret exists for the given id.
    async fn exists(&self, id: &str) -> Result<bool, VaultError>;
}

/// Backend that can enumerate stored secret IDs.
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
pub trait ListableBackend: SecretBackend {
    /// List IDs of all secrets managed by this backend.
    async fn list(&self) -> Result<Vec<String>, VaultError>;
}
