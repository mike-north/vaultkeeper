//! Native host platform implementation using std::process and std::fs.

use std::path::{Path, PathBuf};
use vaultkeeper_core::backend::{ExecOptions, ExecOutput, HostPlatform, Platform};
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

/// Create a directory (and any missing parents) with owner-only (`0o700`)
/// permissions on Unix, mirroring the TS library's
/// `fs.mkdir(dir, { recursive: true, mode: 0o700 })` contract (see #255) so
/// config/key/secret storage directories created by the native CLI are never
/// left group/world-listable under a permissive umask.
///
/// If `path` already exists, it is left completely untouched — including its
/// permissions — matching the TS side's behavior (`fs.mkdir` with
/// `recursive: true` is a no-op on an existing path) and avoiding a
/// chmod-on-startup surprise for a directory an operator deliberately made
/// more permissive.
///
/// On non-Unix platforms (Windows), only directory creation happens; POSIX
/// mode bits do not apply there.
pub(crate) fn create_dir_all_secure(path: &Path) -> std::io::Result<()> {
    if path.exists() {
        return Ok(());
    }

    std::fs::create_dir_all(path)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }

    Ok(())
}

#[async_trait::async_trait]
impl HostPlatform for NativeHostPlatform {
    async fn exec(
        &self,
        cmd: &str,
        args: &[&str],
        options: ExecOptions<'_>,
    ) -> Result<ExecOutput, VaultError> {
        use std::process::{Command, Stdio};

        let mut command = Command::new(cmd);
        command.args(args);
        if let Some(env) = options.env {
            for (key, value) in env {
                command.env(key, value);
            }
        }
        if let Some(cwd) = options.cwd {
            command.current_dir(cwd);
        }
        command
            .stdin(if options.stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = command.spawn().map_err(|e| VaultError::Exec {
            message: format!("Failed to spawn {cmd}: {e}"),
            command: cmd.to_string(),
        })?;

        if let Some(data) = options.stdin {
            use std::io::Write;
            if let Some(ref mut stdin) = child.stdin {
                stdin.write_all(data).map_err(|e| VaultError::Exec {
                    message: format!("Failed to write stdin for {cmd}: {e}"),
                    command: cmd.to_string(),
                })?;
            }
        }

        let output = child.wait_with_output().map_err(|e| VaultError::Exec {
            message: format!("Failed to wait for {cmd}: {e}"),
            command: cmd.to_string(),
        })?;

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
        // Ensure parent directory exists, created owner-only (0o700) on Unix
        // per #255 — matches the TS library's `fs.mkdir(dir, { mode: 0o700 })`
        // contract for config/key/secret storage directories.
        if let Some(parent) = path.parent() {
            create_dir_all_secure(parent).map_err(|e| VaultError::Filesystem {
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

    // -----------------------------------------------------------------
    // Issue #239: `exec` gains `ExecOptions { stdin, env, cwd }`.
    // -----------------------------------------------------------------

    /// `ExecOptions::default()` (all fields `None`) must reproduce the
    /// pre-#239 3-argument `exec(cmd, args, stdin)` behavior exactly (AC1):
    /// no stdin, inherited environment, inherited cwd.
    #[cfg(unix)]
    #[tokio::test]
    async fn exec_with_default_options_behaves_like_pre_239_exec() {
        let dir = tempfile::tempdir().unwrap();
        let host = NativeHostPlatform::new(dir.path().to_path_buf());
        let output = host
            .exec("echo", &["hello"], ExecOptions::default())
            .await
            .unwrap();
        assert_eq!(output.exit_code, 0);
        assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "hello");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn exec_respects_cwd_option() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("marker.txt"), b"hi").unwrap();
        let host = NativeHostPlatform::new(dir.path().to_path_buf());
        let output = host
            .exec(
                "ls",
                &[],
                ExecOptions {
                    cwd: Some(dir.path()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert!(String::from_utf8_lossy(&output.stdout).contains("marker.txt"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn exec_respects_env_option() {
        let dir = tempfile::tempdir().unwrap();
        let host = NativeHostPlatform::new(dir.path().to_path_buf());
        let output = host
            .exec(
                "sh",
                &["-c", "echo $VAULTKEEPER_TEST_VAR"],
                ExecOptions {
                    env: Some(&[("VAULTKEEPER_TEST_VAR", "hello-239")]),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "hello-239");
    }

    /// AC7 regression: exec failures must classify as `VaultError::Exec`
    /// (distinct from the `HostFilesystemError`/`VaultError::Filesystem`
    /// contract, which is unchanged by #239) even when a *new* option
    /// (`cwd`) is what caused the failure — spawning with a nonexistent
    /// working directory fails at `Command::spawn`.
    #[cfg(unix)]
    #[tokio::test]
    async fn exec_with_nonexistent_cwd_fails_as_exec_error() {
        let dir = tempfile::tempdir().unwrap();
        let host = NativeHostPlatform::new(dir.path().to_path_buf());
        let missing_cwd = dir.path().join("does-not-exist");
        let result = host
            .exec(
                "echo",
                &["hi"],
                ExecOptions {
                    cwd: Some(&missing_cwd),
                    ..Default::default()
                },
            )
            .await;
        match result {
            Err(VaultError::Exec { command, .. }) => assert_eq!(command, "echo"),
            other => panic!("expected VaultError::Exec, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------
    // Issue #255: config/key/secret storage directories must be created
    // 0o700 (owner-only), matching the TS library's
    // `fs.mkdir(dir, { recursive: true, mode: 0o700 })` contract.
    // -----------------------------------------------------------------

    /// AC1 + AC3: a directory implicitly created by `write_file` (via its
    /// parent-directory mkdir step) must end up `0o700` on Unix, not
    /// whatever the umask would otherwise produce (e.g. `0o755`).
    #[cfg(unix)]
    #[tokio::test]
    async fn write_file_creates_missing_parent_dir_as_0700() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let host = NativeHostPlatform::new(dir.path().to_path_buf());
        let nested = dir.path().join("fresh-config-dir");
        let target = nested.join("keys.enc");

        host.write_file(&target, b"secret", 0o600).await.unwrap();

        let mode = fs::metadata(&nested).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "freshly created parent dir must be 0o700");
    }

    /// AC2: an already-existing directory with broader permissions must be
    /// left untouched by `write_file` — no chmod-on-startup surprise for a
    /// directory an operator deliberately made more permissive.
    #[cfg(unix)]
    #[tokio::test]
    async fn write_file_leaves_existing_wider_permission_dir_untouched() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let host = NativeHostPlatform::new(dir.path().to_path_buf());
        let existing = dir.path().join("already-here");
        fs::create_dir(&existing).unwrap();
        fs::set_permissions(&existing, fs::Permissions::from_mode(0o755)).unwrap();
        let target = existing.join("keys.enc");

        host.write_file(&target, b"secret", 0o600).await.unwrap();

        let mode = fs::metadata(&existing).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o755,
            "pre-existing directory permissions must be left untouched"
        );
    }

    /// Non-Unix (Windows) sanity check: `create_dir_all_secure` still
    /// creates the directory even though POSIX mode bits don't apply there.
    #[cfg(not(unix))]
    #[tokio::test]
    async fn write_file_creates_missing_parent_dir_on_non_unix() {
        let dir = tempfile::tempdir().unwrap();
        let host = NativeHostPlatform::new(dir.path().to_path_buf());
        let nested = dir.path().join("fresh-config-dir");
        let target = nested.join("keys.enc");

        host.write_file(&target, b"secret", 0o600).await.unwrap();

        assert!(nested.is_dir());
    }

    /// AC2 on non-Unix: an already-existing directory is left alone (no
    /// error, no attempted recreation) by `create_dir_all_secure`.
    #[cfg(not(unix))]
    #[tokio::test]
    async fn write_file_leaves_existing_dir_untouched_on_non_unix() {
        let dir = tempfile::tempdir().unwrap();
        let host = NativeHostPlatform::new(dir.path().to_path_buf());
        let existing = dir.path().join("already-here");
        fs::create_dir(&existing).unwrap();
        let target = existing.join("keys.enc");

        host.write_file(&target, b"secret", 0o600).await.unwrap();

        assert!(existing.is_dir());
    }
}
