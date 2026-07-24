//! User-acceptance tests for `run --token`/`exec` (issue #333, folding
//! `exec` into `run` as a second source alongside `--profile`).
//!
//! These exercise the real subprocess paths end to end — the compiled
//! `vaultkeeper` binary launching a real child process — never a mocked or
//! hand-built approximation. A real, redeemable JWE is minted with
//! `vaultkeeper_core::VaultKeeper::setup` against a `HostPlatform` rooted at
//! the *same* config dir the CLI subprocess under test is pointed at (the
//! same pattern `cli_integration.rs`'s `session_mint` tests use to enroll a
//! signing key before spawning the CLI) — the persisted key material is what
//! lets the subprocess's own `authorize()` decrypt it.

#![cfg(unix)]

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use tempfile::TempDir;
use vaultkeeper_core::backend::{ExecOptions, ExecOutput, HostPlatform, Platform};
use vaultkeeper_core::errors::VaultError;
use vaultkeeper_core::vault::{SetupOptions, VaultKeeper, VaultKeeperOptions};

fn vk_bin() -> &'static str {
    env!("CARGO_BIN_EXE_vaultkeeper")
}

/// A `HostPlatform` backed by the real filesystem, scoped to a single config
/// directory — just enough to mint a token via `VaultKeeper::setup` (which
/// persists key material to disk) before spawning the CLI subprocess under
/// test at the same `VAULTKEEPER_CONFIG_DIR`.
struct RealFsHost {
    config_dir: PathBuf,
}

#[async_trait::async_trait]
impl HostPlatform for RealFsHost {
    async fn exec(
        &self,
        _cmd: &str,
        _args: &[&str],
        _options: ExecOptions<'_>,
    ) -> Result<ExecOutput, VaultError> {
        Ok(ExecOutput {
            stdout: Vec::new(),
            stderr: Vec::new(),
            exit_code: 0,
        })
    }
    async fn read_file(&self, path: &Path) -> Result<Vec<u8>, VaultError> {
        std::fs::read(path).map_err(|e| VaultError::Filesystem {
            message: format!("read {}: {e}", path.display()),
            path: path.display().to_string(),
            permission: "read".to_string(),
            code: None,
        })
    }
    async fn write_file(&self, path: &Path, content: &[u8], _mode: u32) -> Result<(), VaultError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| VaultError::Filesystem {
                message: format!("mkdir {}: {e}", parent.display()),
                path: parent.display().to_string(),
                permission: "write".to_string(),
                code: None,
            })?;
        }
        std::fs::write(path, content).map_err(|e| VaultError::Filesystem {
            message: format!("write {}: {e}", path.display()),
            path: path.display().to_string(),
            permission: "write".to_string(),
            code: None,
        })
    }
    async fn file_exists(&self, path: &Path) -> Result<bool, VaultError> {
        Ok(path.exists())
    }
    async fn delete_file(&self, path: &Path) -> Result<(), VaultError> {
        std::fs::remove_file(path).map_err(|e| VaultError::Filesystem {
            message: format!("delete {}: {e}", path.display()),
            path: path.display().to_string(),
            permission: "write".to_string(),
            code: None,
        })
    }
    async fn rename_file(&self, from: &Path, to: &Path) -> Result<(), VaultError> {
        std::fs::rename(from, to).map_err(|e| VaultError::Filesystem {
            message: format!("rename {} -> {}: {e}", from.display(), to.display()),
            path: to.display().to_string(),
            permission: "write".to_string(),
            code: None,
        })
    }
    async fn list_dir(&self, path: &Path) -> Result<Vec<String>, VaultError> {
        match std::fs::read_dir(path) {
            Ok(entries) => Ok(entries
                .filter_map(|e| e.ok().and_then(|e| e.file_name().into_string().ok()))
                .collect()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(VaultError::Filesystem {
                message: format!("readdir {}: {e}", path.display()),
                path: path.display().to_string(),
                permission: "read".to_string(),
                code: None,
            }),
        }
    }
    fn platform(&self) -> Platform {
        Platform::Linux
    }
    fn config_dir(&self) -> &Path {
        &self.config_dir
    }
}

fn write_config(dir: &TempDir) {
    let config = serde_json::json!({
        "version": 1,
        "backends": [{ "type": "file", "enabled": true }],
        "keyRotation": { "gracePeriodDays": 7 },
        "defaults": { "ttlMinutes": 60, "trustTier": "3" }
    });
    fs::write(
        dir.path().join("config.json"),
        serde_json::to_string_pretty(&config).unwrap(),
    )
    .expect("failed to write config");
}

/// Mint a real, redeemable secret JWE (`skip_trust: true` — a "dev"-bound
/// token, the simplest kind `authorize()` accepts) embedding `secret_value`,
/// persisting key material to `dir` so a CLI subprocess pointed at the same
/// config dir can decrypt it.
async fn mint_token(dir: &TempDir, secret_value: &str) -> String {
    let host = Arc::new(RealFsHost {
        config_dir: dir.path().to_path_buf(),
    });
    let vault = VaultKeeper::init(
        host.as_ref(),
        Some(VaultKeeperOptions {
            skip_doctor: true,
            ..Default::default()
        }),
    )
    .await
    .expect("failed to init vault for minting");
    vault
        .setup(
            host.as_ref(),
            "run-token-uat-secret",
            secret_value,
            Some(&SetupOptions {
                ttl_minutes: None,
                use_limit: None,
                executable_path: None,
                skip_trust: Some(true),
                trust_tier: None,
                backend_type: None,
            }),
        )
        .await
        .expect("failed to mint token")
}

// ─── AC1: run --token matches exec --token byte-for-byte ─────────

#[tokio::test]
async fn run_token_injects_the_secret_as_vaultkeeper_secret_by_default() {
    let dir = TempDir::new().unwrap();
    write_config(&dir);
    let token = mint_token(&dir, "the-real-secret-value").await;

    let output = Command::new(vk_bin())
        .env("VAULTKEEPER_CONFIG_DIR", dir.path())
        .args([
            "run",
            "--token",
            &token,
            "--",
            "sh",
            "-c",
            "printf '%s' \"$VAULTKEEPER_SECRET\"",
        ])
        .stdin(Stdio::null())
        .output()
        .expect("failed to run");

    assert!(output.status.success());
    assert_eq!(output.stdout, b"the-real-secret-value");
}

#[tokio::test]
async fn run_token_and_exec_token_produce_byte_identical_stdout_and_exit_code() {
    let dir = TempDir::new().unwrap();
    write_config(&dir);
    let token = mint_token(&dir, "byte-exact-comparison-value").await;

    let run_output = Command::new(vk_bin())
        .env("VAULTKEEPER_CONFIG_DIR", dir.path())
        .args([
            "run",
            "--token",
            &token,
            "--",
            "sh",
            "-c",
            "printf '%s|exit=%s' \"$VAULTKEEPER_SECRET\" \"$?\"",
        ])
        .stdin(Stdio::null())
        .output()
        .expect("failed to run `run --token`");

    let exec_output = Command::new(vk_bin())
        .env("VAULTKEEPER_CONFIG_DIR", dir.path())
        .args([
            "exec",
            "--token",
            &token,
            "--",
            "sh",
            "-c",
            "printf '%s|exit=%s' \"$VAULTKEEPER_SECRET\" \"$?\"",
        ])
        .stdin(Stdio::null())
        .output()
        .expect("failed to run `exec`");

    assert!(run_output.status.success());
    assert!(exec_output.status.success());
    assert_eq!(
        run_output.stdout, exec_output.stdout,
        "run --token and exec --token must inject the identical child \
         environment/stdout — the whole point of folding exec into run"
    );
    assert_eq!(run_output.status.code(), exec_output.status.code());
}

// ─── AC2: --as renames the target var; invalid names rejected ────

#[tokio::test]
async fn run_token_as_renames_the_injected_variable() {
    let dir = TempDir::new().unwrap();
    write_config(&dir);
    let token = mint_token(&dir, "custom-var-value").await;

    let output = Command::new(vk_bin())
        .env("VAULTKEEPER_CONFIG_DIR", dir.path())
        .args([
            "run",
            "--token",
            &token,
            "--as",
            "CUSTOM_VAR",
            "--",
            "sh",
            "-c",
            "printf 'default=%s custom=%s' \"${VAULTKEEPER_SECRET:-unset}\" \"$CUSTOM_VAR\"",
        ])
        .stdin(Stdio::null())
        .output()
        .expect("failed to run");

    assert!(output.status.success());
    assert_eq!(
        output.stdout,
        b"default=unset custom=custom-var-value".as_slice()
    );
}

#[test]
fn run_token_rejects_an_invalid_as_var_name_with_a_typed_error() {
    let dir = TempDir::new().unwrap();
    write_config(&dir);

    let output = Command::new(vk_bin())
        .env("VAULTKEEPER_CONFIG_DIR", dir.path())
        .args([
            "run",
            "--token",
            "irrelevant",
            "--as",
            "lower_case",
            "--",
            "true",
        ])
        .stdin(Stdio::null())
        .output()
        .expect("failed to run");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--as"));
    assert!(stderr.contains("lower_case"));
}

// ─── AC3: --token conflicts with --profile/--profile-file ────────

#[test]
fn run_rejects_token_and_profile_together_naming_the_conflict() {
    let dir = TempDir::new().unwrap();
    write_config(&dir);

    let output = Command::new(vk_bin())
        .env("VAULTKEEPER_CONFIG_DIR", dir.path())
        .args([
            "run",
            "--profile",
            "x",
            "--token",
            "irrelevant",
            "--",
            "true",
        ])
        .stdin(Stdio::null())
        .output()
        .expect("failed to run");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--profile"));
    assert!(stderr.contains("--token"));
}

#[test]
fn run_rejects_token_and_profile_file_together_naming_the_conflict() {
    let dir = TempDir::new().unwrap();
    write_config(&dir);

    let output = Command::new(vk_bin())
        .env("VAULTKEEPER_CONFIG_DIR", dir.path())
        .args([
            "run",
            "--profile-file",
            "/tmp/whatever.json",
            "--token",
            "irrelevant",
            "--",
            "true",
        ])
        .stdin(Stdio::null())
        .output()
        .expect("failed to run");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--profile-file"));
    assert!(stderr.contains("--token"));
}

// --token combinable with --set, into the same launched environment.
#[tokio::test]
async fn run_token_combines_with_set_into_the_same_environment() {
    let dir = TempDir::new().unwrap();
    write_config(&dir);
    let token = mint_token(&dir, "token-value").await;

    // Store the --set-referenced secret via the real `store` command.
    let mut store = Command::new(vk_bin())
        .env("VAULTKEEPER_CONFIG_DIR", dir.path())
        .args(["store", "--name", "extra-secret"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn store");
    use std::io::Write;
    store
        .stdin
        .take()
        .unwrap()
        .write_all(b"extra-secret-value")
        .unwrap();
    assert!(store.wait().unwrap().success());

    let output = Command::new(vk_bin())
        .env("VAULTKEEPER_CONFIG_DIR", dir.path())
        .args([
            "run",
            "--token",
            &token,
            "--set",
            "EXTRA=extra-secret",
            "--",
            "sh",
            "-c",
            "printf 'token=%s extra=%s' \"$VAULTKEEPER_SECRET\" \"$EXTRA\"",
        ])
        .stdin(Stdio::null())
        .output()
        .expect("failed to run");

    assert!(output.status.success());
    assert_eq!(
        output.stdout,
        b"token=token-value extra=extra-secret-value".as_slice()
    );
}

// ─── AC4: exec still works; deprecation notice on stderr only ────

#[tokio::test]
async fn exec_still_works_and_notices_go_to_stderr_only() {
    let dir = TempDir::new().unwrap();
    write_config(&dir);
    let token = mint_token(&dir, "still-works-value").await;

    let output = Command::new(vk_bin())
        .env("VAULTKEEPER_CONFIG_DIR", dir.path())
        .args([
            "exec",
            "--token",
            &token,
            "--",
            "sh",
            "-c",
            "printf '%s' \"$VAULTKEEPER_SECRET\"",
        ])
        .stdin(Stdio::null())
        .output()
        .expect("failed to run exec");

    assert!(output.status.success());
    assert_eq!(output.stdout, b"still-works-value");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("deprecated"),
        "exec must emit a deprecation notice, got: {stderr}"
    );
    assert!(!stderr.contains("still-works-value"));
}

/// AC4's "stdout byte-identical with and without the notice-bearing
/// stderr": the deprecation notice living on stderr must never perturb
/// stdout — proven by comparing `exec`'s stdout to `run --token`'s (the
/// underlying operation without any notice at all).
#[tokio::test]
async fn exec_stdout_is_byte_identical_to_run_token_stdout_despite_the_stderr_notice() {
    let dir = TempDir::new().unwrap();
    write_config(&dir);
    let token = mint_token(&dir, "identical-stdout-value").await;

    let exec_output = Command::new(vk_bin())
        .env("VAULTKEEPER_CONFIG_DIR", dir.path())
        .args([
            "exec",
            "--token",
            &token,
            "--",
            "sh",
            "-c",
            "printf '%s' \"$VAULTKEEPER_SECRET\"",
        ])
        .stdin(Stdio::null())
        .output()
        .expect("failed to run exec");

    let run_output = Command::new(vk_bin())
        .env("VAULTKEEPER_CONFIG_DIR", dir.path())
        .args([
            "run",
            "--token",
            &token,
            "--",
            "sh",
            "-c",
            "printf '%s' \"$VAULTKEEPER_SECRET\"",
        ])
        .stdin(Stdio::null())
        .output()
        .expect("failed to run `run --token`");

    assert_eq!(exec_output.stdout, run_output.stdout);
    // exec's stderr carries the notice; run's does not.
    assert!(String::from_utf8_lossy(&exec_output.stderr).contains("deprecated"));
    assert!(!String::from_utf8_lossy(&run_output.stderr).contains("deprecated"));
}

#[test]
fn exec_help_documents_the_deprecation_and_points_at_run_token() {
    let mut child = Command::new(vk_bin())
        .args(["exec", "--help"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .spawn()
        .expect("failed to run");
    let mut stdout = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut stdout)
        .unwrap();
    child.wait().unwrap();

    assert!(
        stdout.to_lowercase().contains("deprecated"),
        "exec --help must document the deprecation, got: {stdout}"
    );
    assert!(
        stdout.contains("run --token"),
        "exec --help must point at run --token, got: {stdout}"
    );
}

#[test]
fn exec_is_hidden_from_the_top_level_help_list() {
    let mut child = Command::new(vk_bin())
        .args(["--help"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .spawn()
        .expect("failed to run");
    let mut stdout = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut stdout)
        .unwrap();
    child.wait().unwrap();

    assert!(!stdout.contains("exec"), "got: {stdout}");
}
