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
    /// `write_file`'s implicit parent-dir creation. Mirrors the `file/`-dir
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
