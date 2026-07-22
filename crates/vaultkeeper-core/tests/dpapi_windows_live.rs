//! Windows-only live round-trip test for `DpapiBackend` (issue #292, AC5).
//!
//! `ProtectedData.Protect`/`Unprotect` require a real Windows user session
//! (`CurrentUser` scope works headless, but still needs a real Windows OS),
//! so this file only compiles on `target_os = "windows"` (see the crate-level
//! `cfg` gate below) — on every other platform it is empty. No Windows CI
//! runner is configured for this repository yet, so in practice this test
//! currently only runs when executed locally on Windows; it exists so that
//! adding a Windows CI runner later requires no further test code.
//!
//! This intentionally does **not** validate against a *committed* fixture
//! blob the way `keys::storage`'s `ts-written-keystate` fixtures do
//! (`crates/vaultkeeper-core/tests/fixtures/ts-written-keystate/`): that
//! fixture's AES-256-GCM envelope is keyed by a portable `.keys.wrap`
//! secret, but DPAPI's `CurrentUser` scope derives its protection key from
//! the invoking Windows account's own credentials/SID — a blob produced by
//! one Windows user is not decryptable by a different user or machine, so no
//! blob committed to this repo could be portably re-decrypted by CI. Instead
//! this test exercises a live round trip within a single run (proving the
//! real `ProtectedData` envelope + entry-path scheme this port shares with
//! the TS backend actually works end-to-end), and the mocked-`exec` unit
//! tests in `crates/vaultkeeper-core/src/backend/dpapi.rs` separately pin
//! down that the constructed PowerShell script and stdin payload have the
//! same shape as the TS reference implementation.

#![cfg(target_os = "windows")]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use vaultkeeper_core::backend::{
    DpapiBackend, ExecOptions, ExecOutput, HostPlatform, Platform, SecretBackend,
};
use vaultkeeper_core::errors::VaultError;

/// Minimal native host: real subprocess exec via `std::process::Command`,
/// real filesystem I/O via `std::fs`, scoped to a temp directory per test.
struct WindowsNativeHost {
    config_dir: PathBuf,
}

#[async_trait::async_trait]
impl HostPlatform for WindowsNativeHost {
    async fn exec(
        &self,
        cmd: &str,
        args: &[&str],
        options: ExecOptions<'_>,
    ) -> Result<ExecOutput, VaultError> {
        use std::io::Write;
        use std::process::{Command, Stdio};

        let mut child = Command::new(cmd)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| VaultError::Exec {
                message: format!("failed to spawn {cmd}: {e}"),
                command: cmd.to_string(),
            })?;

        if let Some(stdin_bytes) = options.stdin {
            child
                .stdin
                .take()
                .expect("stdin piped")
                .write_all(stdin_bytes)
                .map_err(|e| VaultError::Exec {
                    message: format!("failed to write stdin to {cmd}: {e}"),
                    command: cmd.to_string(),
                })?;
        }

        let output = child.wait_with_output().map_err(|e| VaultError::Exec {
            message: format!("failed to wait for {cmd}: {e}"),
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
            message: format!("failed to read {}: {e}", path.display()),
            path: path.display().to_string(),
            permission: "read".to_string(),
            code: e.raw_os_error().map(|c| c.to_string()),
        })
    }

    async fn write_file(&self, path: &Path, content: &[u8], _mode: u32) -> Result<(), VaultError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| VaultError::Filesystem {
                message: format!("failed to create {}: {e}", parent.display()),
                path: parent.display().to_string(),
                permission: "write".to_string(),
                code: e.raw_os_error().map(|c| c.to_string()),
            })?;
        }
        std::fs::write(path, content).map_err(|e| VaultError::Filesystem {
            message: format!("failed to write {}: {e}", path.display()),
            path: path.display().to_string(),
            permission: "write".to_string(),
            code: e.raw_os_error().map(|c| c.to_string()),
        })
    }

    async fn file_exists(&self, path: &Path) -> Result<bool, VaultError> {
        Ok(path.exists())
    }

    async fn delete_file(&self, path: &Path) -> Result<(), VaultError> {
        std::fs::remove_file(path).map_err(|e| VaultError::Filesystem {
            message: format!("failed to delete {}: {e}", path.display()),
            path: path.display().to_string(),
            permission: "delete".to_string(),
            code: e.raw_os_error().map(|c| c.to_string()),
        })
    }

    async fn list_dir(&self, path: &Path) -> Result<Vec<String>, VaultError> {
        let mut names = Vec::new();
        let entries = match std::fs::read_dir(path) {
            Ok(entries) => entries,
            Err(_) => return Ok(Vec::new()),
        };
        for entry in entries {
            let entry = entry.map_err(|e| VaultError::Filesystem {
                message: format!("failed to list {}: {e}", path.display()),
                path: path.display().to_string(),
                permission: "list".to_string(),
                code: e.raw_os_error().map(|c| c.to_string()),
            })?;
            names.push(entry.file_name().to_string_lossy().into_owned());
        }
        Ok(names)
    }

    fn platform(&self) -> Platform {
        Platform::Windows
    }

    fn config_dir(&self) -> &Path {
        &self.config_dir
    }
}

fn temp_dir(name: &str) -> PathBuf {
    let mut dir = std::env::temp_dir();
    dir.push(format!(
        "vaultkeeper-dpapi-live-{name}-{}",
        std::process::id()
    ));
    dir
}

#[tokio::test]
async fn live_dpapi_round_trip_current_user_scope() {
    let config_dir = temp_dir("config");
    let host: Arc<dyn HostPlatform> = Arc::new(WindowsNativeHost {
        config_dir: config_dir.clone(),
    });
    let backend = DpapiBackend::new(host, None);

    assert!(
        backend.is_available().await,
        "DPAPI backend should be available on a Windows runner"
    );

    let secret = "live-round-trip-\"quoted\"\nwith newline and 日本語 🔐";
    backend.store("live-id", secret).await.unwrap();
    let retrieved = backend.retrieve("live-id").await.unwrap();
    assert_eq!(retrieved, secret);

    backend.delete("live-id").await.unwrap();
    let err = backend.retrieve("live-id").await.unwrap_err();
    assert!(matches!(err, VaultError::SecretNotFound { .. }));

    let _ = std::fs::remove_dir_all(&config_dir);
}
