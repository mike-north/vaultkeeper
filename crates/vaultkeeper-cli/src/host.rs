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
            // The native host does not yet derive a symbolic errno code from
            // `std::io::Error` (out of scope here — see issue #138); only the
            // WASM host bridge currently populates `code`.
            code: None,
        })
    }

    async fn write_file(&self, path: &Path, content: &[u8], mode: u32) -> Result<(), VaultError> {
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| VaultError::Filesystem {
                message: format!("Failed to create directory {}: {e}", parent.display()),
                path: parent.display().to_string(),
                permission: "write".to_string(),
                code: None,
            })?;
        }

        std::fs::write(path, content).map_err(|e| VaultError::Filesystem {
            message: format!("Failed to write {}: {e}", path.display()),
            path: path.display().to_string(),
            permission: "write".to_string(),
            code: None,
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
                code: None,
            })?;
        }

        let _ = mode; // suppress unused warning on non-Unix
        Ok(())
    }

    async fn file_exists(&self, path: &Path) -> Result<bool, VaultError> {
        // `Path::exists()` swallows every error (including EACCES) and
        // reports `false`, which would let a permission failure masquerade
        // as "does not exist" for callers (like FileBackend::retrieve) that
        // rely on this to distinguish the two. Use `metadata` directly so
        // only a genuine ENOENT-equivalent maps to `Ok(false)`.
        match std::fs::metadata(path) {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(VaultError::Filesystem {
                message: format!("Failed to check existence of {}: {e}", path.display()),
                path: path.display().to_string(),
                permission: "read".to_string(),
                code: None,
            }),
        }
    }

    async fn delete_file(&self, path: &Path) -> Result<(), VaultError> {
        std::fs::remove_file(path).map_err(|e| VaultError::Filesystem {
            message: format!("Failed to delete {}: {e}", path.display()),
            path: path.display().to_string(),
            permission: "write".to_string(),
            code: None,
        })
    }

    // `std::fs::rename` replaces an existing `to` on every platform Rust
    // supports it on — including Windows, via `MoveFileExW`/
    // `SetFileInformationByHandle` — per its own documented contract
    // ("Renames a file or directory to a new name, replacing the original
    // file if `to` already exists", https://doc.rust-lang.org/std/fs/fn.rename.html).
    // The historical Windows footgun in this area (rust-lang/rust#31301) was
    // specifically about renaming one *directory* over another, not the
    // plain-file replace this call always performs (`keys.enc.<suffix>.tmp`
    // over `keys.enc`), so no platform-specific fallback is needed here.
    async fn rename_file(&self, from: &Path, to: &Path) -> Result<(), VaultError> {
        std::fs::rename(from, to).map_err(|e| VaultError::Filesystem {
            message: format!(
                "Failed to rename {} to {}: {e}",
                from.display(),
                to.display()
            ),
            path: to.display().to_string(),
            permission: "write".to_string(),
            code: None,
        })
    }

    async fn list_dir(&self, path: &Path) -> Result<Vec<String>, VaultError> {
        match std::fs::read_dir(path) {
            Ok(entries) => {
                let mut names = Vec::new();
                for entry in entries {
                    if let Ok(e) = entry
                        && let Some(name) = e.file_name().to_str()
                    {
                        names.push(name.to_string());
                    }
                }
                Ok(names)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(VaultError::Filesystem {
                message: format!("Failed to list {}: {e}", path.display()),
                path: path.display().to_string(),
                permission: "read".to_string(),
                code: None,
            }),
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Regression test for PR #135 review feedback: `file_exists` must map a
    /// genuine "does not exist" (ENOENT) to `Ok(false)`, not lose that
    /// distinction the way `Path::exists()` does.
    #[tokio::test]
    async fn file_exists_returns_false_for_missing_path() {
        let dir = tempfile::tempdir().unwrap();
        let host = NativeHostPlatform::new(dir.path().to_path_buf());
        let missing = dir.path().join("does-not-exist");
        assert!(!host.file_exists(&missing).await.unwrap());
    }

    #[tokio::test]
    async fn file_exists_returns_true_for_existing_path() {
        let dir = tempfile::tempdir().unwrap();
        let host = NativeHostPlatform::new(dir.path().to_path_buf());
        let present = dir.path().join("present.txt");
        fs::write(&present, b"hi").unwrap();
        assert!(host.file_exists(&present).await.unwrap());
    }

    /// Regression test for PR #135 review feedback: `Path::exists()`
    /// swallows every error (including EACCES) and reports `false`, which
    /// would let `FileBackend::retrieve()`'s exists-probe misreport a
    /// permission failure as "does not exist". `file_exists` must instead
    /// surface a genuine stat failure (here: an inaccessible parent
    /// directory) as `VaultError::Filesystem`.
    #[cfg(unix)]
    #[tokio::test]
    async fn file_exists_surfaces_filesystem_error_when_probe_is_denied() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let host = NativeHostPlatform::new(dir.path().to_path_buf());
        let blocked_dir = dir.path().join("blocked");
        fs::create_dir(&blocked_dir).unwrap();
        let entry = blocked_dir.join("secret.enc");
        fs::write(&entry, b"data").unwrap();
        // Remove search permission on the parent so stat'ing the child fails
        // with EACCES rather than ENOENT.
        fs::set_permissions(&blocked_dir, fs::Permissions::from_mode(0o000)).unwrap();

        let result = host.file_exists(&entry).await;
        // Restore permissions unconditionally so the tempdir can be cleaned up.
        fs::set_permissions(&blocked_dir, fs::Permissions::from_mode(0o700)).unwrap();

        match result {
            // Running with elevated privileges (e.g. root in CI) bypasses
            // permission bits entirely, so there's nothing to assert.
            Ok(_) => {}
            Err(VaultError::Filesystem { permission, .. }) => assert_eq!(permission, "read"),
            Err(other) => panic!("expected VaultError::Filesystem, got {other:?}"),
        }
    }
}
