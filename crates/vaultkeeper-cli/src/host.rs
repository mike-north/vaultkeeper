//! Native host platform implementation using std::process and std::fs.

use std::path::{Path, PathBuf};
use vaultkeeper_core::backend::{ExecOutput, HostPlatform, Platform};
use vaultkeeper_core::errors::VaultError;

/// Native host platform implementation for the CLI.
pub struct NativeHostPlatform {
    config_dir: PathBuf,
}

impl NativeHostPlatform {
    /// Create a new native host platform.
    pub fn new(config_dir: PathBuf) -> Self {
        Self { config_dir }
    }

    /// Get the platform-appropriate default config directory.
    pub fn default_config_dir() -> PathBuf {
        if let Ok(dir) = std::env::var("VAULTKEEPER_CONFIG_DIR")
            && !dir.is_empty()
        {
            return PathBuf::from(dir);
        }

        if cfg!(target_os = "windows") {
            if let Ok(appdata) = std::env::var("APPDATA") {
                return PathBuf::from(appdata).join("vaultkeeper");
            }
            let home = dirs_fallback();
            return home.join("AppData").join("Roaming").join("vaultkeeper");
        }

        let home = dirs_fallback();
        home.join(".config").join("vaultkeeper")
    }
}

fn dirs_fallback() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp"))
}

#[async_trait::async_trait]
impl HostPlatform for NativeHostPlatform {
    async fn exec(
        &self,
        cmd: &str,
        args: &[&str],
        stdin_data: Option<&[u8]>,
    ) -> Result<ExecOutput, VaultError> {
        use std::process::{Command, Stdio};

        let mut child = Command::new(cmd)
            .args(args)
            .stdin(if stdin_data.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| VaultError::Other(format!("Failed to spawn {cmd}: {e}")))?;

        if let Some(data) = stdin_data {
            use std::io::Write;
            if let Some(ref mut stdin) = child.stdin {
                stdin
                    .write_all(data)
                    .map_err(|e| VaultError::Other(format!("Failed to write stdin: {e}")))?;
            }
        }

        let output = child
            .wait_with_output()
            .map_err(|e| VaultError::Other(format!("Failed to wait for {cmd}: {e}")))?;

        Ok(ExecOutput {
            stdout: output.stdout,
            stderr: output.stderr,
            exit_code: output.status.code().unwrap_or(-1),
        })
    }

    async fn read_file(&self, path: &Path) -> Result<Vec<u8>, VaultError> {
        std::fs::read(path).map_err(|e| VaultError::Filesystem {
            message: format!("Failed to read {}: {e}", path.display()),
            path: path.display().to_string(),
            permission: "read".to_string(),
        })
    }

    async fn write_file(&self, path: &Path, content: &[u8], mode: u32) -> Result<(), VaultError> {
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| VaultError::Filesystem {
                message: format!("Failed to create directory {}: {e}", parent.display()),
                path: parent.display().to_string(),
                permission: "write".to_string(),
            })?;
        }

        std::fs::write(path, content).map_err(|e| VaultError::Filesystem {
            message: format!("Failed to write {}: {e}", path.display()),
            path: path.display().to_string(),
            permission: "write".to_string(),
        })?;

        // Set permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(mode);
            std::fs::set_permissions(path, perms).map_err(|e| VaultError::Filesystem {
                message: format!("Failed to set permissions on {}: {e}", path.display()),
                path: path.display().to_string(),
                permission: "write".to_string(),
            })?;
        }

        let _ = mode; // suppress unused warning on non-Unix
        Ok(())
    }

    async fn file_exists(&self, path: &Path) -> Result<bool, VaultError> {
        Ok(path.exists())
    }

    fn platform(&self) -> Platform {
        if cfg!(target_os = "macos") {
            Platform::Darwin
        } else if cfg!(target_os = "windows") {
            Platform::Windows
        } else {
            Platform::Linux
        }
    }

    fn config_dir(&self) -> &Path {
        &self.config_dir
    }
}
