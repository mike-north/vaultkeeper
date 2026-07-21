//! Linux conformance test for [`vaultkeeper_core::backend::SecretToolBackend`]
//! against the *real* `secret-tool(1)` binary and a live D-Bus Secret Service
//! session (issue #291, AC5).
//!
//! # Why this lives here, not in `vaultkeeper-conformance`
//!
//! The `vaultkeeper-conformance` crate's cases are CLI-level: each case
//! spawns the `vaultkeeper` binary with a fixed argv and asserts on its
//! stdout/stderr/exit code. The native CLI does not yet support selecting a
//! backend at the command line (`--backend secret-tool`) — that wiring is a
//! separate, not-yet-landed epic item (`vaultkeeper-core` issue #273,
//! "fail-closed config-driven backend registry"). Until that lands there is
//! no CLI invocation this test could shell out to that would exercise
//! `SecretToolBackend` specifically, so this test instead drives the backend
//! directly (the same shape the doctor and unit-test suites already use for
//! host-platform-dependent checks) while still sharing assertion *data* with
//! the CLI-level conformance suite: the id/secret pair below is read
//! straight out of `vaultkeeper_conformance::all_cases()`'s
//! `"store succeeds with valid secret"` case rather than being duplicated by
//! hand, so a change to that shared fixture updates both suites together.
//!
//! # Gating
//!
//! This test talks to a *real* Secret Service daemon over D-Bus and is only
//! meaningful on Linux with `secret-tool` installed and a session bus
//! reachable (in CI: `dbus-run-session -- cargo test -p vaultkeeper-core
//! --test secret_tool_conformance`, which exports `DBUS_SESSION_BUS_ADDRESS`
//! for the duration of the session). Everywhere else — this sandboxed
//! development environment included, which is macOS — the test detects the
//! missing prerequisite and skips itself with a clear message rather than
//! failing or silently vanishing, mirroring the existing
//! `describe.skipIf(RUST_BIN === null)` pattern the JS conformance runner
//! uses when the Rust binary isn't available
//! (`packages/cli-tests/test/conformance/run-conformance.test.ts`).

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use vaultkeeper_core::backend::{
    ExecOptions, ExecOutput, HostPlatform, ListableBackend, Platform, SecretBackend,
    SecretToolBackend,
};
use vaultkeeper_core::errors::VaultError;

/// Minimal real `HostPlatform` sufficient for `SecretToolBackend`, which
/// never touches the filesystem. File methods are unreachable in practice —
/// they panic instead of silently doing the wrong thing if that assumption
/// ever changes.
struct RealLinuxHost {
    config_dir: PathBuf,
}

#[async_trait::async_trait]
impl HostPlatform for RealLinuxHost {
    async fn exec(
        &self,
        cmd: &str,
        args: &[&str],
        options: ExecOptions<'_>,
    ) -> Result<ExecOutput, VaultError> {
        let mut command = Command::new(cmd);
        command.args(args);
        command.stdin(if options.stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        });
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());

        let mut child = command
            .spawn()
            .map_err(|e| VaultError::Other(format!("Failed to spawn {cmd}: {e}")))?;

        if let Some(data) = options.stdin {
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

    async fn read_file(&self, _path: &Path) -> Result<Vec<u8>, VaultError> {
        unreachable!("SecretToolBackend never touches the filesystem")
    }

    async fn write_file(
        &self,
        _path: &Path,
        _content: &[u8],
        _mode: u32,
    ) -> Result<(), VaultError> {
        unreachable!("SecretToolBackend never touches the filesystem")
    }

    async fn file_exists(&self, _path: &Path) -> Result<bool, VaultError> {
        unreachable!("SecretToolBackend never touches the filesystem")
    }

    async fn delete_file(&self, _path: &Path) -> Result<(), VaultError> {
        unreachable!("SecretToolBackend never touches the filesystem")
    }

    async fn list_dir(&self, _path: &Path) -> Result<Vec<String>, VaultError> {
        unreachable!("SecretToolBackend never touches the filesystem")
    }

    fn platform(&self) -> Platform {
        Platform::Linux
    }

    fn config_dir(&self) -> &Path {
        &self.config_dir
    }
}

/// Extract the `--name`/stdin fixture the CLI-level conformance suite
/// already asserts on, so this test's id/secret aren't a second,
/// hand-duplicated copy of that data.
fn shared_store_fixture() -> (String, String) {
    let case = vaultkeeper_conformance::all_cases()
        .into_iter()
        .find(|c| c.name == "store succeeds with valid secret")
        .expect("vaultkeeper-conformance must define 'store succeeds with valid secret'");

    let name_flag_pos = case
        .command
        .iter()
        .position(|arg| arg == "--name")
        .expect("case must pass --name");
    let name = case.command[name_flag_pos + 1].clone();
    let secret = case.stdin.expect("case must supply stdin secret");
    (name, secret)
}

/// True only when this test can plausibly reach a real Secret Service:
/// Linux, `secret-tool` on PATH, and a session bus address exported (as
/// `dbus-run-session` does for the whole invocation).
fn secret_tool_environment_available() -> bool {
    if !cfg!(target_os = "linux") {
        return false;
    }
    if std::env::var("DBUS_SESSION_BUS_ADDRESS").is_err() {
        return false;
    }
    Command::new("secret-tool")
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

#[tokio::test]
async fn secret_tool_backend_conformance_against_real_secret_tool() {
    if !secret_tool_environment_available() {
        eprintln!(
            "skipping secret_tool_backend_conformance_against_real_secret_tool: \
             requires target_os=linux, `secret-tool` on PATH, and \
             DBUS_SESSION_BUS_ADDRESS set (run under `dbus-run-session`). \
             This is expected on non-Linux development machines and CI \
             runners without a session bus (issue #291 AC5)."
        );
        return;
    }

    let host = std::sync::Arc::new(RealLinuxHost {
        config_dir: std::env::temp_dir(),
    });
    let backend = SecretToolBackend::new(host);
    let (name, secret) = shared_store_fixture();
    // Namespace the id so repeated CI runs against a shared session bus
    // don't collide with a leftover entry from a previous run.
    let name = format!("{name}-{}", std::process::id());

    assert!(
        backend.is_available().await,
        "secret-tool must be available"
    );

    backend
        .store(&name, &secret)
        .await
        .expect("store must succeed against a real Secret Service");

    assert!(
        backend.exists(&name).await.unwrap(),
        "exists must be true immediately after store"
    );

    let retrieved = backend
        .retrieve(&name)
        .await
        .expect("retrieve must succeed for a just-stored entry");
    assert_eq!(
        retrieved, secret,
        "retrieved secret must match the stored value byte-for-byte"
    );

    let listed = backend.list().await.expect("list must succeed");
    assert!(
        listed.contains(&name),
        "list must include the just-stored id: {listed:?}"
    );

    backend
        .delete(&name)
        .await
        .expect("delete must succeed for an existing entry");

    assert!(
        !backend.exists(&name).await.unwrap(),
        "exists must be false immediately after delete"
    );

    let err = backend
        .retrieve(&name)
        .await
        .expect_err("retrieve of a deleted entry must fail");
    assert!(
        matches!(err, VaultError::SecretNotFound { .. }),
        "expected SecretNotFound after delete, got {err:?}"
    );

    let delete_err = backend
        .delete(&name)
        .await
        .expect_err("deleting an already-deleted entry must fail");
    assert!(
        matches!(delete_err, VaultError::SecretNotFound { .. }),
        "expected SecretNotFound deleting a missing entry, got {delete_err:?}"
    );
}
