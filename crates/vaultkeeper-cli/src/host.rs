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

/// Enumerate native entries without imposing record-file rules on profile lookup.
pub(crate) fn read_directory_entries(path: &Path) -> Result<Vec<std::fs::DirEntry>, VaultError> {
    match std::fs::read_dir(path) {
        Ok(entries) => entries
            .map(|entry| entry.map_err(|error| list_directory_error(path, error)))
            .collect(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(list_directory_error(path, error)),
    }
}

/// A failed enumeration is different from an empty inventory.
fn list_directory_error(path: &Path, error: std::io::Error) -> VaultError {
    VaultError::Filesystem {
        message: format!("Failed to list {}: {error}", path.display()),
        path: path.display().to_string(),
        permission: "read".to_string(),
        code: None,
    }
}

/// Classify errors from linking an owned sibling. Linux filesystems can
/// report EPERM when links are unavailable despite permitting ordinary I/O.
fn hard_link_unavailable(error: &std::io::Error) -> bool {
    if error.kind() == std::io::ErrorKind::Unsupported {
        return true;
    }
    #[cfg(unix)]
    return matches!(error.raw_os_error(), Some(libc::EPERM | libc::ENOSYS));
    #[cfg(windows)]
    {
        // CreateHardLinkW can return ERROR_INVALID_FUNCTION on exFAT.
        const ERROR_INVALID_FUNCTION: i32 = 1;
        const ERROR_NOT_SUPPORTED: i32 = 50;
        return matches!(
            error.raw_os_error(),
            Some(ERROR_INVALID_FUNCTION | ERROR_NOT_SUPPORTED)
        );
    }
    #[cfg(not(any(unix, windows)))]
    false
}

/// Create a directory (and any missing parents), setting owner-only
/// (`0o700`) permissions atomically at creation time on every directory this
/// call actually creates — mirroring the TS library's
/// `fs.mkdir(dir, { recursive: true, mode: 0o700 })` contract (see #255) so
/// config/key/secret storage directories created by the native CLI are never
/// left group/world-listable under a permissive umask.
///
/// The mode is passed to the `mkdir(2)` syscall itself (via
/// `DirBuilderExt::mode`), not applied afterward with a separate
/// `set_permissions` call, so there is no create-then-chmod window: no other
/// process can observe (or race to widen) the directory between creation and
/// its final permissions.
///
/// Any directory in the path that **already exists** — the target itself or
/// an intermediate parent — is left completely untouched, including its
/// permissions. This is deliberately not a preceding `path.exists()` check
/// (which would itself be a TOCTOU race against a concurrent creator);
/// instead, each `mkdir` attempt is made directly and an `AlreadyExists`
/// error is treated as success without ever touching that directory's mode.
/// This matches the TS side's behavior (`fs.mkdir` with `recursive: true` is
/// a no-op on an existing path) and avoids a chmod-on-startup surprise for a
/// directory an operator deliberately made more permissive.
///
/// On non-Unix platforms (Windows), only directory creation happens; POSIX
/// mode bits do not apply there.
pub(crate) fn create_dir_all_secure(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        create_dir_all_secure_unix(path)
    }

    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(path)
    }
}

/// Unix implementation of [`create_dir_all_secure`]: recursively creates
/// missing ancestors (also at `0o700`) before retrying the target, and
/// treats `AlreadyExists` at any level as success without touching that
/// directory's permissions.
#[cfg(unix)]
fn create_dir_all_secure_unix(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;

    match std::fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // A missing parent is the only other reason plain `mkdir` (no
            // `-p`) fails this way; create it first, then retry — treating a
            // second `AlreadyExists` (e.g. a concurrent creator winning the
            // race) as success too.
            match path.parent() {
                Some(parent) => {
                    create_dir_all_secure_unix(parent)?;
                    match std::fs::DirBuilder::new().mode(0o700).create(path) {
                        Ok(()) => Ok(()),
                        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
                        Err(e) => Err(e),
                    }
                }
                None => Err(e),
            }
        }
        Err(e) => Err(e),
    }
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
        use std::io::Write;

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

        let error = |e| VaultError::Filesystem {
            message: format!("Failed to write {}: {e}", path.display()),
            path: path.display().to_string(),
            permission: "write".to_string(),
            code: None,
        };
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        // Newly created wrapping-key stages must be owner-only before the
        // first byte is written, even when atomic publication is unavailable.
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(mode);
        }
        let mut file = options.open(path).map_err(error)?;
        file.write_all(content).map_err(error)?;

        // Set permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(mode);
            file.set_permissions(perms)
                .map_err(|e| VaultError::Filesystem {
                    message: format!("Failed to set permissions on {}: {e}", path.display()),
                    path: path.display().to_string(),
                    permission: "write".to_string(),
                    code: None,
                })?;
        }

        let _ = mode; // suppress unused warning on non-Unix
        Ok(())
    }

    async fn write_file_if_absent(
        &self,
        path: &Path,
        content: &[u8],
        mode: u32,
    ) -> Result<bool, VaultError> {
        use std::io::{ErrorKind, Write};
        use std::sync::atomic::{AtomicU64, Ordering};

        static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

        let error = |e| VaultError::Filesystem {
            message: format!("Failed to publish {}: {e}", path.display()),
            path: path.display().to_string(),
            permission: "write".to_string(),
            code: None,
        };
        let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
        if let Some(parent) = parent {
            create_dir_all_secure(parent).map_err(error)?;
        }

        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(mode);
        }
        let _ = mode;

        let (temp, mut file) = loop {
            let counter = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            // A short sibling keeps staging within the wrapping-key path budget.
            let temp = path.with_file_name(format!(".v{:x}-{counter:x}", std::process::id()));
            match options.open(&temp) {
                Ok(file) => break (temp, file),
                Err(e) if e.kind() == ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(error(e)),
            }
        };

        let written = file.write_all(content);
        #[cfg(unix)]
        let written = written.and_then(|()| {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(mode))
        });
        drop(file);
        let published =
            written
                .map_err(error)
                .and_then(|()| match std::fs::hard_link(&temp, path) {
                    Ok(()) => Ok(true),
                    Err(e) if e.kind() == ErrorKind::AlreadyExists => Ok(false),
                    // Only a link capability failure permits the core's
                    // sequential wrapping-key fallback for ordinary storage.
                    Err(e) if hard_link_unavailable(&e) => Err(VaultError::LockingNotSupported {
                        message: format!("Cannot atomically publish {}: {e}", path.display()),
                    }),
                    Err(e) => Err(error(e)),
                });
        // Publication is the commit point. Cleanup cannot turn it into a failure.
        let _ = std::fs::remove_file(&temp);
        published
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
        let mut names = Vec::new();
        for entry in read_directory_entries(path)? {
            if entry
                .file_type()
                .map_err(|error| list_directory_error(path, error))?
                .is_file()
                && let Some(name) = entry.file_name().to_str()
            {
                names.push(name.to_string());
            }
        }
        Ok(names)
    }

    /// Real `O_EXCL`-based exclusive create, overriding the trait's
    /// fail-closed default (see that method's doc comment in
    /// `vaultkeeper-core`). `std::fs::OpenOptions::create_new(true)` maps to
    /// `O_EXCL` on Unix and `CREATE_NEW` on Windows — both atomically fail
    /// with "already exists" rather than racing a separate exists-check
    /// against a subsequent create.
    async fn try_create_lock_file(&self, path: &Path, content: &[u8]) -> Result<(), VaultError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| VaultError::Filesystem {
                message: format!("Failed to create directory {}: {e}", parent.display()),
                path: parent.display().to_string(),
                permission: "lock".to_string(),
                code: None,
            })?;
        }

        let file = match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
        {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(VaultError::Filesystem {
                    message: format!("Lock contention: {} is already held", path.display()),
                    path: path.display().to_string(),
                    permission: "lock".to_string(),
                    code: Some("EEXIST".to_string()),
                });
            }
            Err(e) => {
                return Err(VaultError::Filesystem {
                    message: format!("Failed to create lock file {}: {e}", path.display()),
                    path: path.display().to_string(),
                    permission: "lock".to_string(),
                    code: None,
                });
            }
        };

        write_lock_file_contents(path, file, content)
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

/// Write `content` to an already-`create_new`-opened lock `file` at `path`,
/// setting owner-only permissions on success.
///
/// Split out of [`NativeHostPlatform::try_create_lock_file`] so the
/// write-failure cleanup path below is directly unit-testable (see
/// `try_create_lock_file_cleans_up_the_lock_file_when_the_write_fails`)
/// without needing to force a real `O_EXCL` create to be immediately
/// followed by a real write failure (disk full, quota, etc.) end-to-end.
fn write_lock_file_contents(
    path: &Path,
    mut file: std::fs::File,
    content: &[u8],
) -> Result<(), VaultError> {
    use std::io::Write;

    if let Err(e) = file.write_all(content) {
        // The caller's `create_new` already succeeded, so an empty (or
        // partially written) lock file now exists at `path`. Leaving it
        // behind on this error path would create a permanent phantom
        // lock: every future acquirer sees the path occupied and treats
        // it as genuine contention, with no marker content for
        // `take_over_if_stale` (in `vaultkeeper-core`) to ever recognize
        // as its own stale format — it would sit there forever. Clean it
        // up before returning the write failure. Best-effort: if the
        // delete itself also fails (e.g. the same disk-full condition
        // that caused the write to fail), there is nothing more this
        // function can do about it — the write error is still the one
        // that matters to the caller.
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(VaultError::Filesystem {
            message: format!("Failed to write lock file {}: {e}", path.display()),
            path: path.display().to_string(),
            permission: "lock".to_string(),
            code: None,
        });
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Best-effort — a permission-setting failure on an already
        // successfully created/written lock file is not itself a
        // reason to fail lock acquisition.
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Record inventories consume filenames, so a matching directory must never be opened.
    #[tokio::test]
    async fn list_dir_returns_regular_files_only() {
        let dir = tempfile::tempdir().unwrap();
        let host = NativeHostPlatform::new(dir.path().to_path_buf());
        fs::create_dir(dir.path().join("616c706861.enc")).unwrap();
        fs::write(dir.path().join("62657461.enc"), b"entry").unwrap();

        assert_eq!(host.list_dir(dir.path()).await.unwrap(), ["62657461.enc"]);
    }

    /// Ordinary persistence can recover from a missing link primitive.
    /// A write-permission failure must still propagate to the caller.
    #[test]
    fn hard_link_unavailability_preserves_permission_errors() {
        use std::io::{Error, ErrorKind};

        assert!(hard_link_unavailable(&Error::from(ErrorKind::Unsupported)));
        assert!(!hard_link_unavailable(&Error::from(
            ErrorKind::PermissionDenied
        )));
        #[cfg(unix)]
        {
            assert!(hard_link_unavailable(&Error::from_raw_os_error(
                libc::EPERM
            )));
            assert!(!hard_link_unavailable(&Error::from_raw_os_error(
                libc::EACCES
            )));
        }
        #[cfg(windows)]
        {
            assert!(hard_link_unavailable(&Error::from_raw_os_error(1)));
            assert!(hard_link_unavailable(&Error::from_raw_os_error(50)));
            assert!(!hard_link_unavailable(&Error::from_raw_os_error(5)));
        }
    }

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
    ///
    /// With the atomic `DirBuilder`-based implementation, this exercises the
    /// `AlreadyExists` branch of `create_dir_all_secure` directly (there is
    /// no longer a separate `exists()` pre-check to short-circuit through),
    /// so it genuinely proves the guard, not just an early return.
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

    /// AC1 regression for review feedback on #255: when multiple levels are
    /// missing, *every* directory the call creates must land `0o700`, not
    /// just the immediate (leaf) parent. The original implementation ran
    /// plain `create_dir_all` (all missing levels at the umask default) and
    /// then `set_permissions` on only the final path component, so an
    /// intermediate directory like `grandparent` here could be left at
    /// e.g. `0o755` under a permissive umask.
    #[cfg(unix)]
    #[tokio::test]
    async fn create_dir_all_secure_tightens_every_newly_created_level() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("grandparent").join("parent").join("leaf");

        super::create_dir_all_secure(&target).unwrap();

        for level in [
            dir.path().join("grandparent"),
            dir.path().join("grandparent").join("parent"),
            target.clone(),
        ] {
            let mode = fs::metadata(&level).unwrap().permissions().mode() & 0o777;
            assert_eq!(
                mode,
                0o700,
                "every newly created directory (not just the leaf) must be 0o700: {}",
                level.display()
            );
        }
    }

    /// AC1 + AC2 regression: when an intermediate ancestor already exists
    /// with broader permissions, it must be left untouched while the
    /// directories actually created underneath it are still tightened to
    /// `0o700`.
    #[cfg(unix)]
    #[tokio::test]
    async fn create_dir_all_secure_preserves_existing_ancestor_while_tightening_new_ones() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let ancestor = dir.path().join("existing-ancestor");
        fs::create_dir(&ancestor).unwrap();
        fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o755)).unwrap();
        let target = ancestor.join("new-parent").join("leaf");

        super::create_dir_all_secure(&target).unwrap();

        let ancestor_mode = fs::metadata(&ancestor).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            ancestor_mode, 0o755,
            "pre-existing ancestor permissions must be left untouched"
        );
        let new_parent_mode = fs::metadata(ancestor.join("new-parent"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            new_parent_mode, 0o700,
            "newly created directory under an existing ancestor must still be 0o700"
        );
    }

    /// Regression test for the TOCTOU race flagged in #255 review: a
    /// `path.exists()` pre-check followed by an unconditional
    /// `set_permissions` after `create_dir_all` leaves a window in which a
    /// concurrent actor can create the target directory (with whatever
    /// permissions it chooses) between the check and the create/chmod —
    /// and the old code would then unconditionally chmod that
    /// concurrently-created directory to `0o700`, silently overriding
    /// permissions someone else deliberately set (an AC2 violation that
    /// only manifests under real concurrency, not in a single-threaded
    /// call). The atomic `DirBuilder::mode` + `AlreadyExists`-as-no-op
    /// implementation has no such window: mode is set atomically at
    /// creation, and losing the creation race never triggers a
    /// `set_permissions` call at all. This test races many iterations of
    /// "concurrent creator wins" against `create_dir_all_secure` and
    /// asserts the concurrent creator's permissions always survive.
    #[cfg(unix)]
    #[test]
    fn create_dir_all_secure_never_reclaims_a_concurrently_created_directory() {
        use std::os::unix::fs::PermissionsExt;
        use std::sync::Barrier;
        use std::sync::atomic::{AtomicBool, Ordering};

        for _ in 0..25 {
            let dir = tempfile::tempdir().unwrap();
            let target = dir.path().join("racing-dir");
            let barrier = Barrier::new(2);
            let concurrent_actor_won = AtomicBool::new(false);

            std::thread::scope(|scope| {
                scope.spawn(|| {
                    barrier.wait();
                    // Simulate a concurrent actor racing to create the same
                    // directory with deliberately wider permissions.
                    if fs::create_dir(&target).is_ok() {
                        fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).unwrap();
                        concurrent_actor_won.store(true, Ordering::SeqCst);
                    }
                });

                barrier.wait();
                let _ = super::create_dir_all_secure(&target);
            });

            let mode = fs::metadata(&target).unwrap().permissions().mode() & 0o777;
            if concurrent_actor_won.load(Ordering::SeqCst) {
                assert_eq!(
                    mode, 0o755,
                    "a directory created concurrently by another actor must never be \
                     reclaimed/re-chmodded by create_dir_all_secure"
                );
            } else {
                assert_eq!(
                    mode, 0o700,
                    "when create_dir_all_secure wins the creation race it must still \
                     produce 0o700"
                );
            }
        }
    }

    /// Signing-key private material (issue #289) is sealed under
    /// `<config_dir>/signing/`, a directory `FileBackend::generate_signing_key`
    /// creates the same way every other storage directory is created — via
    /// the host's implicit parent-dir creation. Mirrors the `file/`-dir
    /// permission tests above: driven through the real production path
    /// (`FileBackend` + `NativeHostPlatform`, not the generic `write_file`
    /// helper directly), this proves `signing/` itself, not just an
    /// arbitrary directory, lands owner-only `0o700` and is never left at a
    /// permissive umask default.
    #[cfg(unix)]
    #[tokio::test]
    async fn generate_signing_key_creates_signing_dir_as_0700() {
        use std::os::unix::fs::PermissionsExt;
        use std::sync::Arc;
        use vaultkeeper_core::backend::{FileBackend, SigningBackend};
        use vaultkeeper_core::types::SigningAlgorithm;

        let dir = tempfile::tempdir().unwrap();
        let host = Arc::new(NativeHostPlatform::new(dir.path().to_path_buf()));
        let backend = FileBackend::new(host);

        backend
            .generate_signing_key("cli-signing-key", SigningAlgorithm::EdDsa)
            .await
            .unwrap();

        let signing_dir = dir.path().join("signing");
        let mode = fs::metadata(&signing_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o700,
            "freshly created signing/ dir must be 0o700, got {mode:o}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn racing_signing_creators_agree_with_a_reopened_native_store() {
        use std::sync::Arc;
        use tokio::sync::Barrier;
        use vaultkeeper_core::backend::{FileBackend, SigningBackend};
        use vaultkeeper_core::types::SigningAlgorithm;

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let enroll = |barrier: Arc<Barrier>, backend: FileBackend| async move {
            barrier.wait().await;
            backend
                .generate_signing_key("release", SigningAlgorithm::EdDsa)
                .await?;
            backend.get_public_key("release").await
        };
        let barrier = Arc::new(Barrier::new(2));
        let open = || FileBackend::new(Arc::new(NativeHostPlatform::new(root.clone())));
        let first = tokio::spawn(enroll(Arc::clone(&barrier), open()));
        let second = tokio::spawn(enroll(barrier, open()));

        let (winner, loser) = match (first.await.unwrap(), second.await.unwrap()) {
            (Ok(key), Err(err)) | (Err(err), Ok(key)) => (key, err),
            outcome => panic!("expected one successful enrollment, got {outcome:?}"),
        };
        assert!(matches!(loser, VaultError::SigningKeyAlreadyExists { .. }));
        let persisted = open().get_public_key("release").await.unwrap();
        assert_eq!(winner.public_key_pem, persisted.public_key_pem);
        assert_eq!(winner.kid, persisted.kid);
        assert_eq!(winner.algorithm, persisted.algorithm);
        assert_eq!(fs::read_dir(root.join("signing")).unwrap().count(), 1);
    }

    /// A complete candidate left by an interrupted repair still selects the
    /// wrapping key for native signing enrollments in the same store.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn signing_enrollment_resumes_interrupted_wrap_key_repair() {
        use std::sync::Arc;
        use vaultkeeper_core::backend::{FileBackend, SigningBackend};
        use vaultkeeper_core::types::SigningAlgorithm;

        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join(".keys.wrap");
        let repair_path = dir.path().join(".keys.wrap.r");
        let candidate = [0x42; 32];
        let host = NativeHostPlatform::new(dir.path().to_path_buf());
        host.write_file(&key_path, &[0], 0o600).await.unwrap();
        host.write_file(&repair_path, &candidate, 0o600)
            .await
            .unwrap();

        let open = || FileBackend::new(Arc::new(NativeHostPlatform::new(dir.path().to_path_buf())));
        let enroll = |backend: FileBackend, label: &'static str| async move {
            backend
                .generate_signing_key(label, SigningAlgorithm::EdDsa)
                .await
                .unwrap();
            backend.get_public_key(label).await.unwrap().kid
        };
        let first = tokio::spawn(enroll(open(), "first"));
        let second = tokio::spawn(enroll(open(), "second"));
        let (first_kid, second_kid) = (first.await.unwrap(), second.await.unwrap());

        assert!(fs::read(&key_path).unwrap() == candidate);
        assert!(!repair_path.exists());
        let reopened = open();
        assert_eq!(
            reopened.get_public_key("first").await.unwrap().kid,
            first_kid
        );
        assert_eq!(
            reopened.get_public_key("second").await.unwrap().kid,
            second_kid
        );
    }

    /// The valid wrapping key and its repair candidate fit in a 990-byte
    /// config directory. Installing the repair must fit there as well.
    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn signing_enrollment_repairs_wrap_key_at_macos_path_boundary() {
        use std::sync::Arc;
        use vaultkeeper_core::backend::{FileBackend, SigningBackend};
        use vaultkeeper_core::types::SigningAlgorithm;

        let dir = tempfile::tempdir().unwrap();
        let mut root = dir.path().to_path_buf();
        while root.as_os_str().len() < 990 {
            let remaining = 989 - root.as_os_str().len();
            let component = if remaining == 201 {
                199
            } else {
                remaining.min(200)
            };
            root.push("a".repeat(component));
        }
        assert_eq!(root.as_os_str().len(), 990);
        let key_path = root.join(".keys.wrap");
        let repair_path = root.join(".keys.wrap.r");
        let candidate = [0x42; 32];
        let host = Arc::new(NativeHostPlatform::new(root));
        host.write_file(&key_path, &[0], 0o600).await.unwrap();
        host.write_file(&repair_path, &candidate, 0o600)
            .await
            .unwrap();

        let backend = FileBackend::new(host);
        backend
            .generate_signing_key("a", SigningAlgorithm::EdDsa)
            .await
            .unwrap();
        assert!(fs::read(&key_path).unwrap() == candidate);
        assert!(!repair_path.exists());
        assert!(backend.get_public_key("a").await.is_ok());
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

    // -------------------------------------------------------------------
    // `try_create_lock_file` (issue #322) — real `O_EXCL` semantics, and
    // the genuinely-concurrent revocation-state guarantee it's built to
    // support.
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn try_create_lock_file_succeeds_on_a_fresh_path() {
        let dir = tempfile::tempdir().unwrap();
        let host = NativeHostPlatform::new(dir.path().to_path_buf());
        let lock_path = dir.path().join("keys.enc.lock");

        host.try_create_lock_file(&lock_path, b"12345")
            .await
            .unwrap();

        assert_eq!(fs::read(&lock_path).unwrap(), b"12345");
    }

    /// The second `O_EXCL` create against an already-held lock must fail
    /// with the specific `Filesystem { permission: "lock", code: Some("EEXIST") }`
    /// shape `keys::storage`'s lock acquisition matches on to distinguish
    /// contention from a genuine I/O failure.
    #[tokio::test]
    async fn try_create_lock_file_reports_contention_as_typed_eexist() {
        let dir = tempfile::tempdir().unwrap();
        let host = NativeHostPlatform::new(dir.path().to_path_buf());
        let lock_path = dir.path().join("keys.enc.lock");

        host.try_create_lock_file(&lock_path, b"first")
            .await
            .unwrap();
        let err = host
            .try_create_lock_file(&lock_path, b"second")
            .await
            .unwrap_err();

        match err {
            VaultError::Filesystem {
                permission, code, ..
            } => {
                assert_eq!(permission, "lock");
                assert_eq!(code.as_deref(), Some("EEXIST"));
            }
            other => panic!("expected VaultError::Filesystem, got {other:?}"),
        }
        // The original holder's content must survive an unsuccessful
        // contender's create attempt untouched.
        assert_eq!(fs::read(&lock_path).unwrap(), b"first");
    }

    #[tokio::test]
    async fn try_create_lock_file_creates_missing_parent_dir() {
        let dir = tempfile::tempdir().unwrap();
        let host = NativeHostPlatform::new(dir.path().to_path_buf());
        let lock_path = dir.path().join("fresh-config-dir").join("keys.enc.lock");

        host.try_create_lock_file(&lock_path, b"x").await.unwrap();

        assert!(lock_path.exists());
    }

    /// Regression test for issue #322 review feedback: if `write_all` fails
    /// after `create_new` already succeeded, the just-created lock file must
    /// not be left behind — otherwise it becomes a permanent phantom lock
    /// (every future acquirer sees the path occupied and treats it as
    /// contention forever, since its content never matches the
    /// `take_over_if_stale` marker format).
    ///
    /// This exercises `write_lock_file_contents` (the extracted helper
    /// `try_create_lock_file` delegates to after its own `create_new`
    /// succeeds) directly, handing it a deliberately write-incapable
    /// `File` — opened read-only, so `write_all` fails immediately and
    /// deterministically with a real OS error (no rlimit/signal tricks
    /// needed, and nothing that could destabilize other tests running
    /// concurrently in the same process). This proves the exact behavior
    /// `try_create_lock_file` relies on this helper for: the real
    /// `create_new`-then-write sequence in `try_create_lock_file` above
    /// composes with it unchanged, so this is not testing an approximation
    /// of the production path — it's testing the actual cleanup code that
    /// path calls.
    #[test]
    fn try_create_lock_file_cleans_up_the_lock_file_when_the_write_fails() {
        let dir = tempfile::tempdir().unwrap();
        let lock_path = dir.path().join("keys.enc.lock");

        // Pre-create the file exactly as `create_new` would have (empty,
        // present at `lock_path`), then hand `write_lock_file_contents` a
        // read-only handle to it so the `write_all` call inside fails.
        fs::write(&lock_path, b"").unwrap();
        let read_only_file = fs::OpenOptions::new().read(true).open(&lock_path).unwrap();

        let err = write_lock_file_contents(&lock_path, read_only_file, b"12345").unwrap_err();

        match err {
            VaultError::Filesystem { permission, .. } => assert_eq!(permission, "lock"),
            other => panic!("expected VaultError::Filesystem, got {other:?}"),
        }
        assert!(
            !lock_path.exists(),
            "a lock file must not survive a write failure that happened right after its own \
             creation — it would otherwise become a permanent phantom lock"
        );
    }

    /// AC10 (issue #322): a real `session revoke` and a real `rotateKey`
    /// issued from two genuinely concurrent tasks — scheduled on separate OS
    /// threads by a multi-worker tokio runtime, with no barrier forcing one
    /// to complete before the other starts — against the same real
    /// `NativeHostPlatform` config directory. This is a real overlapping
    /// race, not two sequential calls dressed up as concurrent: both tasks'
    /// `mutate_revocation_state`/`save_key_state` read-modify-write windows
    /// are free to interleave on real disk I/O. Neither writer's mutation is
    /// lost.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn ac10_genuinely_concurrent_revoke_and_rotate_lose_neither_mutation() {
        use std::sync::Arc;
        use vaultkeeper_core::keys::{
            KeyMaterial, KeyStateSnapshot, load_key_state, load_revocation_for_validation,
            mutate_revocation_state, save_key_state,
        };

        let dir = tempfile::tempdir().unwrap();
        let host = Arc::new(NativeHostPlatform::new(dir.path().to_path_buf()));

        let seed = KeyMaterial {
            id: "k-seed".to_string(),
            key: vec![0x01; 32],
            created_at: 1_705_314_600,
        };
        save_key_state(
            host.as_ref(),
            &KeyStateSnapshot {
                current: seed,
                previous: None,
                grace_period_expires_at_ms: None,
            },
        )
        .await
        .unwrap();

        let revoke_host = Arc::clone(&host);
        let revoke_task = tokio::spawn(async move {
            mutate_revocation_state(revoke_host.as_ref(), |state| {
                state.revoke_jti("concurrent-revoke-jti", 9_999_999_999);
            })
            .await
            .unwrap();
        });

        let rotate_host = Arc::clone(&host);
        let rotate_task = tokio::spawn(async move {
            save_key_state(
                rotate_host.as_ref(),
                &KeyStateSnapshot {
                    current: KeyMaterial {
                        id: "k-rotated".to_string(),
                        key: vec![0x02; 32],
                        created_at: 1_705_314_700,
                    },
                    previous: Some(KeyMaterial {
                        id: "k-seed".to_string(),
                        key: vec![0x01; 32],
                        created_at: 1_705_314_600,
                    }),
                    // Fixed far-future timestamp — the grace period's exact
                    // value is irrelevant to this test, only that a
                    // `previous` key round-trips untouched by the
                    // concurrent revoke.
                    grace_period_expires_at_ms: Some(4_000_000_000_000),
                },
            )
            .await
            .unwrap();
        });

        let (revoke_result, rotate_result) = tokio::join!(revoke_task, rotate_task);
        revoke_result.unwrap();
        rotate_result.unwrap();

        let key_state = load_key_state(host.as_ref()).await.unwrap().unwrap();
        assert_eq!(
            key_state.current.id, "k-rotated",
            "rotateKey's mutation must not be lost to a concurrent session revoke"
        );

        let revocation = load_revocation_for_validation(host.as_ref(), 0)
            .await
            .unwrap();
        assert!(
            revocation.is_jti_revoked("concurrent-revoke-jti"),
            "session revoke's mutation must not be lost to a concurrent rotateKey"
        );
    }

    /// Same shape as the revoke/rotate race above, but with many concurrent
    /// revokers racing each other — the scenario most likely to actually
    /// exercise lock contention (not just a single pairwise race that a fast
    /// filesystem might happen to serialize on its own). Every one of 24
    /// concurrently-issued revocations against a shared jti namespace must
    /// survive.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn ac10_many_genuinely_concurrent_revokers_lose_no_mutation() {
        use std::sync::Arc;
        use vaultkeeper_core::keys::{
            KeyMaterial, KeyStateSnapshot, load_revocation_for_validation, mutate_revocation_state,
            save_key_state,
        };

        const N: usize = 24;

        let dir = tempfile::tempdir().unwrap();
        let host = Arc::new(NativeHostPlatform::new(dir.path().to_path_buf()));

        save_key_state(
            host.as_ref(),
            &KeyStateSnapshot {
                current: KeyMaterial {
                    id: "k-seed".to_string(),
                    key: vec![0x03; 32],
                    created_at: 1_705_314_600,
                },
                previous: None,
                grace_period_expires_at_ms: None,
            },
        )
        .await
        .unwrap();

        let mut tasks = Vec::with_capacity(N);
        for i in 0..N {
            let task_host = Arc::clone(&host);
            tasks.push(tokio::spawn(async move {
                mutate_revocation_state(task_host.as_ref(), move |state| {
                    state.revoke_jti(format!("jti-{i}"), 9_999_999_999);
                })
                .await
                .unwrap();
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }

        let revocation = load_revocation_for_validation(host.as_ref(), 0)
            .await
            .unwrap();
        for i in 0..N {
            assert!(
                revocation.is_jti_revoked(&format!("jti-{i}")),
                "revocation of jti-{i} was lost to a concurrent writer"
            );
        }
    }

    /// Stale-lock takeover, exercised against the real filesystem primitive:
    /// a lock file left behind with a timestamp far in the past (simulating
    /// a holder that crashed or panicked before releasing) does not
    /// permanently wedge acquisition — a fresh `mutate_revocation_state`
    /// call still succeeds.
    #[tokio::test]
    async fn stale_lock_file_does_not_wedge_native_acquisition() {
        use vaultkeeper_core::keys::{KeyMaterial, KeyStateSnapshot};
        use vaultkeeper_core::keys::{mutate_revocation_state, save_key_state};

        let dir = tempfile::tempdir().unwrap();
        let host = NativeHostPlatform::new(dir.path().to_path_buf());

        save_key_state(
            &host,
            &KeyStateSnapshot {
                current: KeyMaterial {
                    id: "k-seed".to_string(),
                    key: vec![0x04; 32],
                    created_at: 1_705_314_600,
                },
                previous: None,
                grace_period_expires_at_ms: None,
            },
        )
        .await
        .unwrap();

        // Simulate an abandoned lock: a lock file whose acquisition
        // timestamp is far enough in the past to be considered stale.
        let lock_path = dir.path().join("keys.enc.lock");
        fs::write(&lock_path, b"0").unwrap();

        // Without takeover this would time out waiting for a lock nothing
        // will ever release.
        mutate_revocation_state(&host, |state| {
            state.revoke_jti("post-takeover-jti", 9_999_999_999);
        })
        .await
        .unwrap();
    }

    // ── StubTool through a real HostPlatform::exec (issue #313 AC2) ────────
    //
    // Exercise file and subprocess behavior through the native host. The paired
    // secret-tool double covers argv, stdin, and error classification. The
    // YubiKey fixture isolates pathname behavior from device availability.
    #[cfg(unix)]
    mod stub_tool_backends {
        use super::*;
        use serial_test::serial;
        use std::os::unix::fs::{PermissionsExt, symlink};
        use std::sync::Arc;
        use vaultkeeper_core::backend::{
            ListableBackend, SecretBackend, SecretToolBackend, YubikeyBackend,
        };
        use vaultkeeper_stub_tools::{SENTINEL_ENV_VAR, WORLD_PATH_ENV_VAR};

        /// Locates the compiled `vk-stub-secret-tool` binary the same way
        /// `packages/cli-tests`' JS conformance runner locates the
        /// `vaultkeeper` binary: relative to the workspace's `target/debug`.
        /// `cargo test` at the workspace root always builds it first (it's
        /// a bin target of the sibling `vaultkeeper-stub-tools` crate); a
        /// scoped `cargo test -p vaultkeeper-cli` run without that crate
        /// having been built is the one case this returns `None` for.
        fn find_stub_binary() -> Option<std::path::PathBuf> {
            let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            let workspace_root = manifest_dir.parent()?.parent()?;
            let candidate = workspace_root
                .join("target")
                .join("debug")
                .join("vk-stub-secret-tool");
            candidate.exists().then_some(candidate)
        }

        /// Exposes test tools on the test process's `PATH` and isolates the
        /// paired double's persisted world. This mutates the environment, hence
        /// `#[serial]`: `NativeHostPlatform::exec` inherits the process
        /// environment wholesale (it has no per-call `PATH` override), so
        /// two of these tests running concurrently would race each other's
        /// `PATH`/sentinel mutation.
        struct Fixture {
            path_dir: tempfile::TempDir,
            _world_dir: tempfile::TempDir,
            previous_path: Option<String>,
        }

        impl Fixture {
            fn new() -> Self {
                let path_dir = tempfile::tempdir().unwrap();

                // The stub is a fresh process per `exec` call, so its
                // `World` (the store `secret-tool store` writes into) must
                // be persisted to a file a later `secret-tool lookup`
                // process reads back from — otherwise every invocation
                // would see an empty world and "store" would appear to
                // silently do nothing.
                let world_dir = tempfile::tempdir().unwrap();
                let world_path = world_dir.path().join("world.json");

                let previous_path = std::env::var("PATH").ok();
                let mut new_path = path_dir.path().display().to_string();
                if let Some(existing) = &previous_path {
                    new_path.push(':');
                    new_path.push_str(existing);
                }
                // SAFETY: serialized by `#[serial]` — no concurrent reader
                // of `PATH`/the sentinel/world-path vars in this process
                // while a `Fixture` is alive.
                unsafe {
                    std::env::set_var("PATH", &new_path);
                    std::env::set_var(SENTINEL_ENV_VAR, "1");
                    std::env::set_var(WORLD_PATH_ENV_VAR, &world_path);
                }

                Self {
                    path_dir,
                    _world_dir: world_dir,
                    previous_path,
                }
            }

            /// Expose the paired double only under this fixture's test command name.
            fn with_secret_tool(stub_binary: &Path) -> Self {
                let fixture = Self::new();
                symlink(stub_binary, fixture.path_dir.path().join("secret-tool")).unwrap();
                fixture
            }

            /// Supply device responses so the inventory tests exercise the real filesystem.
            fn with_yubikey() -> Self {
                let fixture = Self::new();
                let tool = fixture.path_dir.path().join("ykman");
                fs::write(
                    &tool,
                    b"#!/bin/sh\n\
                      case \"$1\" in\n\
                      --version|list) echo test-device ;;\n\
                      otp) echo deadbeefcafe01234567deadbeefcafe01234567 ;;\n\
                      *) exit 1 ;;\n\
                      esac\n",
                )
                .unwrap();
                fs::set_permissions(tool, fs::Permissions::from_mode(0o700)).unwrap();
                fixture
            }
        }

        impl Drop for Fixture {
            fn drop(&mut self) {
                // SAFETY: see `Fixture::new`.
                unsafe {
                    match &self.previous_path {
                        Some(p) => std::env::set_var("PATH", p),
                        None => std::env::remove_var("PATH"),
                    }
                    std::env::remove_var(SENTINEL_ENV_VAR);
                    std::env::remove_var(WORLD_PATH_ENV_VAR);
                }
            }
        }

        #[tokio::test]
        #[serial(stub_tool_path_env)]
        async fn secret_tool_backend_store_retrieve_delete_round_trip_through_the_real_stub_binary()
        {
            let Some(stub_binary) = find_stub_binary() else {
                eprintln!(
                    "skipping: vk-stub-secret-tool not built at target/debug \
                     (run `cargo test` from the workspace root, not `-p vaultkeeper-cli` alone)"
                );
                return;
            };
            let _fixture = Fixture::with_secret_tool(&stub_binary);

            let config_dir = tempfile::tempdir().unwrap();
            let host =
                std::sync::Arc::new(NativeHostPlatform::new(config_dir.path().to_path_buf()));
            let backend = SecretToolBackend::new(host);

            let id = "ac2-round-trip";
            assert!(!backend.exists(id).await.unwrap());

            backend.store(id, "s3cret-value").await.unwrap();
            assert!(backend.exists(id).await.unwrap());
            assert_eq!(backend.retrieve(id).await.unwrap(), "s3cret-value");

            backend.delete(id).await.unwrap();
            assert!(!backend.exists(id).await.unwrap());
        }

        #[tokio::test]
        #[serial(stub_tool_path_env)]
        async fn secret_tool_backend_retrieve_of_a_never_stored_id_classifies_as_secret_not_found()
        {
            let Some(stub_binary) = find_stub_binary() else {
                eprintln!(
                    "skipping: vk-stub-secret-tool not built at target/debug \
                     (run `cargo test` from the workspace root, not `-p vaultkeeper-cli` alone)"
                );
                return;
            };
            let _fixture = Fixture::with_secret_tool(&stub_binary);

            let config_dir = tempfile::tempdir().unwrap();
            let host =
                std::sync::Arc::new(NativeHostPlatform::new(config_dir.path().to_path_buf()));
            let backend = SecretToolBackend::new(host);

            let err = backend.retrieve("never-stored-ac2").await.unwrap_err();
            assert!(
                matches!(
                    err,
                    vaultkeeper_core::errors::VaultError::SecretNotFound { .. }
                ),
                "expected SecretNotFound, got {err:?}"
            );
        }

        /// Stores must publish the directory entry itself, leaving symlink targets alone.
        #[tokio::test]
        #[serial(stub_tool_path_env)]
        async fn yubikey_overwrites_a_symlink_with_a_listed_regular_record() {
            let _fixture = Fixture::with_yubikey();
            let dir = tempfile::tempdir().unwrap();
            let host = Arc::new(NativeHostPlatform::new(dir.path().to_path_buf()));
            let storage = dir.path().join("yubikey");
            fs::create_dir(&storage).unwrap();
            let target = dir.path().join("unrelated");
            fs::write(&target, b"keep this file").unwrap();
            let record = storage.join("7a.enc");
            symlink(&target, &record).unwrap();

            YubikeyBackend::new(host.clone(), false)
                .store("z", "value")
                .await
                .unwrap();

            let reopened = YubikeyBackend::new(host, false);
            assert_eq!(reopened.list().await.unwrap(), ["z"]);
            assert_eq!(reopened.retrieve("z").await.unwrap(), "value");
            assert!(fs::symlink_metadata(record).unwrap().is_file());
            assert_eq!(fs::read(target).unwrap(), b"keep this file");
        }

        /// On a folding filesystem a case-only rename still aliases the canonical store path.
        #[tokio::test]
        #[serial(stub_tool_path_env)]
        async fn yubikey_lists_a_successful_store_over_an_uppercase_record_name() {
            let _fixture = Fixture::with_yubikey();
            let dir = tempfile::tempdir().unwrap();
            let host = Arc::new(NativeHostPlatform::new(dir.path().to_path_buf()));
            let backend = YubikeyBackend::new(host.clone(), false);
            backend.store("z", "old value").await.unwrap();
            let storage = dir.path().join("yubikey");
            let canonical = storage.join("7a.enc");
            let uppercase = storage.join("7A.ENC");
            fs::rename(&canonical, &uppercase).unwrap();
            let case_sensitive = !canonical.exists();
            let old_record = fs::read(&uppercase).unwrap();

            backend.store("z", "new value").await.unwrap();

            let reopened = YubikeyBackend::new(host, false);
            assert_eq!(reopened.list().await.unwrap(), ["z"]);
            assert_eq!(reopened.retrieve("z").await.unwrap(), "new value");
            reopened.delete("z").await.unwrap();
            assert!(reopened.list().await.unwrap().is_empty());
            if case_sensitive {
                assert_eq!(fs::read(uppercase).unwrap(), old_record);
            }
        }

        /// Same-directory staging must fit wherever the canonical short record fits.
        #[cfg(target_os = "macos")]
        #[tokio::test]
        #[serial(stub_tool_path_env)]
        async fn yubikey_stores_short_ids_at_the_macos_path_boundary() {
            let _fixture = Fixture::with_yubikey();
            let dir = tempfile::tempdir().unwrap();
            let mut config = dir.path().canonicalize().unwrap();
            // /yubikey/7a.enc uses 15 of the 1023 path bytes.
            while config.as_os_str().len() < 1008 {
                let remaining = 1007 - config.as_os_str().len();
                let component = if remaining == 201 { 199 } else { remaining.min(200) };
                config.push("a".repeat(component));
            }
            let storage = config.join("yubikey");
            fs::create_dir_all(&storage).unwrap();
            fs::write(storage.join("7a.enc"), b"existing record path").unwrap();

            let host = Arc::new(NativeHostPlatform::new(config));
            YubikeyBackend::new(host.clone(), false).store("z", "value").await.unwrap();
            let reopened = YubikeyBackend::new(host, false);
            assert_eq!(reopened.list().await.unwrap(), ["z"]);
            assert_eq!(reopened.retrieve("z").await.unwrap(), "value");
        }
    }
}
