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

use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt, symlink};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Arc;
use std::time::Duration;
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
async fn mint_token_with_limit(
    dir: &TempDir,
    secret_value: &str,
    use_limit: Option<u64>,
) -> (String, String) {
    let host = Arc::new(RealFsHost {
        config_dir: dir.path().to_path_buf(),
    });
    let mut vault = VaultKeeper::init(
        host.as_ref(),
        Some(VaultKeeperOptions {
            skip_doctor: true,
            ..Default::default()
        }),
    )
    .await
    .expect("failed to init vault for minting");
    let token = vault
        .setup(
            host.as_ref(),
            "run-token-uat-secret",
            secret_value,
            Some(&SetupOptions {
                ttl_minutes: None,
                use_limit,
                executable_path: None,
                skip_trust: Some(true),
                trust_tier: None,
                backend_type: None,
            }),
        )
        .await
        .expect("failed to mint token");
    let (handle, claims, _) = vault
        .authorize(&token)
        .expect("minted token must authorize");
    vault.release_handle(&handle);
    let fingerprint = vaultkeeper_core::identity::hash::hash_bytes(claims.jti.as_bytes());
    (token, fingerprint)
}

async fn mint_token(dir: &TempDir, secret_value: &str) -> String {
    mint_token_with_limit(dir, secret_value, None).await.0
}

/// Exercise real authorization while keeping the fixture secret out of argv.
fn run_finite_token(dir: &TempDir, token: &str, verb: &str) -> Command {
    let mut command = Command::new(vk_bin());
    command
        .env("VAULTKEEPER_CONFIG_DIR", dir.path())
        .args([verb, "--token", token])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

fn admit(dir: &TempDir, token: &str, verb: &str) -> Command {
    let mut command = run_finite_token(dir, token, verb);
    command.args(["--", "sh", "-c", "true"]);
    command
}

fn assert_exhausted(output: &Output, limit: u64) {
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(&format!("usage limit of {limit} exceeded")),
        "{stderr}"
    );
}

/// An inaccessible durability handle must not spend the only admission.
#[cfg(unix)]
#[tokio::test]
async fn inaccessible_config_directory_does_not_spend_a_use() {
    let dir = TempDir::new().unwrap();
    write_config(&dir);
    let (token, fingerprint) = mint_token_with_limit(&dir, "finite-secret", Some(1)).await;
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o300)).unwrap();
    // Privileged runners can open a directory despite its mode; they cannot
    // exercise this permission boundary.
    if fs::File::open(dir.path()).is_ok() {
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        return;
    }
    let refused = admit(&dir, &token, "run").output().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("open token usage directory"));
    assert!(
        !dir.path()
            .join("token-usage")
            .join(format!("{fingerprint}.json"))
            .exists()
    );
    let admitted = admit(&dir, &token, "run").output().unwrap();
    assert!(
        admitted.status.success(),
        "{}",
        String::from_utf8_lossy(&admitted.stderr)
    );
}

#[tokio::test]
async fn finite_use_budget_survives_restart_and_serializes_concurrent_admission() {
    let dir = TempDir::new().unwrap();
    write_config(&dir);
    let (token, fingerprint) = mint_token_with_limit(&dir, "finite-secret", Some(3)).await;
    let first = admit(&dir, &token, "run").output().unwrap();
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );

    // The first process has exited. Hold the ledger lock as new contenders start.
    let ledger = dir.path().join("token-usage");
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&ledger)
        .unwrap();
    let gate = OpenOptions::new()
        .create(true)
        .truncate(false)
        .mode(0o600)
        .read(true)
        .write(true)
        .open(ledger.join(format!("{fingerprint}.lock")))
        .unwrap();
    gate.lock().unwrap();
    let mut children: Vec<_> = (0..8)
        .map(|_| admit(&dir, &token, "run").spawn().unwrap())
        .collect();
    tokio::time::sleep(Duration::from_millis(750)).await;
    let exited_while_locked = children
        .iter_mut()
        .any(|child| child.try_wait().unwrap().is_some());
    drop(gate);

    let mut successes = 0;
    for child in children {
        let output = child.wait_with_output().unwrap();
        if output.status.success() {
            successes += 1;
        } else {
            assert_exhausted(&output, 3);
        }
    }
    assert_eq!(
        successes, 2,
        "the first invocation spent one of the three uses"
    );
    assert!(
        !exited_while_locked,
        "admission must wait for the ledger writer"
    );
    assert_exhausted(&admit(&dir, &token, "exec").output().unwrap(), 3);
}

/// A revocation completed while admission waits must deny both launcher verbs
/// before either spends a durable use or reaches the child process.
#[tokio::test]
async fn queued_finite_token_is_refused_after_key_revocation() {
    let dir = TempDir::new().unwrap();
    write_config(&dir);
    let (token, fingerprint) = mint_token_with_limit(&dir, "finite-secret", Some(2)).await;
    let ledger = dir.path().join("token-usage");
    fs::DirBuilder::new().mode(0o700).create(&ledger).unwrap();
    let gate = OpenOptions::new()
        .create_new(true)
        .mode(0o600)
        .read(true)
        .write(true)
        .open(ledger.join(format!("{fingerprint}.lock")))
        .unwrap();
    gate.lock().unwrap();

    let mut children = ["run", "exec"].map(|verb| {
        run_finite_token(&dir, &token, verb)
            .args(["--", "sh", "-c", "printf launched"])
            .spawn()
            .unwrap()
    });
    // Give both launchers a chance to load the old key state and queue while
    // the ledger is locked, as in the concurrent admission test above.
    tokio::time::sleep(Duration::from_millis(750)).await;
    let waited = children
        .iter_mut()
        .all(|child| child.try_wait().unwrap().is_none());
    let revoked = Command::new(vk_bin())
        .env("VAULTKEEPER_CONFIG_DIR", dir.path())
        .arg("revoke-key")
        .output()
        .unwrap();
    drop(gate);
    let results = children.map(|child| child.wait_with_output().unwrap());

    assert!(waited, "the launchers must wait for the ledger lock");
    assert!(
        revoked.status.success(),
        "{}",
        String::from_utf8_lossy(&revoked.stderr)
    );
    for output in results {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(
            (output.status.code(), output.stdout.as_slice()),
            (Some(1), b"".as_slice()),
            "revocation must prevent launch: {stderr}"
        );
        assert!(
            stderr.contains("Token encryption key is no longer eligible"),
            "{stderr}"
        );
    }
    assert!(
        !ledger.join(format!("{fingerprint}.json")).exists(),
        "revocation must leave the durable budget unspent"
    );
}

#[test]
fn usage_lock_owner_fixture() {
    let Some(lock_path) = std::env::var_os("VAULTKEEPER_UAT_USAGE_LOCK") else {
        return;
    };
    let lock = OpenOptions::new()
        .create_new(true)
        .mode(0o600)
        .read(true)
        .write(true)
        .open(lock_path)
        .unwrap();
    lock.lock().unwrap();
    println!("ledger lock acquired");
    std::io::stdout().flush().unwrap();
    // Closing the pipe also releases the fixture if its parent fails early.
    std::io::copy(&mut std::io::stdin().lock(), &mut std::io::sink()).unwrap();
}

#[tokio::test]
async fn killed_lock_owner_leaves_unspent_budget_available() {
    let dir = TempDir::new().unwrap();
    write_config(&dir);
    let (token, fingerprint) = mint_token_with_limit(&dir, "finite-secret", Some(1)).await;
    let ledger = dir.path().join("token-usage");
    fs::DirBuilder::new().mode(0o700).create(&ledger).unwrap();
    let lock_path = ledger.join(format!("{fingerprint}.lock"));
    let mut owner = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "usage_lock_owner_fixture", "--nocapture"])
        .env("VAULTKEEPER_UAT_USAGE_LOCK", &lock_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let acquired = BufReader::new(owner.stdout.take().unwrap())
        .lines()
        .any(|line| line.unwrap() == "ledger lock acquired");
    assert!(acquired, "fixture exited before it acquired the lock");
    fs::write(ledger.join(format!("{fingerprint}.json.tmp")), b"partial").unwrap();
    owner.kill().unwrap();
    assert!(!owner.wait().unwrap().success());
    assert!(
        lock_path.is_file(),
        "the killed owner left the lock inode behind"
    );

    let recovered = admit(&dir, &token, "run").output().unwrap();
    assert!(
        recovered.status.success(),
        "{}",
        String::from_utf8_lossy(&recovered.stderr)
    );
    assert_exhausted(&admit(&dir, &token, "run").output().unwrap(), 1);
}

#[tokio::test]
async fn token_ledger_is_owner_only_with_permissive_umask() {
    let dir = TempDir::new().unwrap();
    write_config(&dir);
    let (token, fingerprint) = mint_token_with_limit(&dir, "finite-secret", Some(1)).await;
    let mut command = admit(&dir, &token, "run");
    // SAFETY: umask only changes the forked child's mask and is async-signal-safe.
    unsafe {
        command.pre_exec(|| {
            libc::umask(0);
            Ok(())
        });
    }
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let ledger = dir.path().join("token-usage");
    let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&ledger), 0o700);
    for extension in ["lock", "json"] {
        let path = ledger.join(format!("{fingerprint}.{extension}"));
        assert_eq!(mode(&path), 0o600);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
        let refused = admit(&dir, &token, "run").output().unwrap();
        assert_eq!(refused.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&refused.stderr).contains("owner-only token usage file"));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }
}

#[tokio::test]
async fn finite_token_refuses_writable_or_redirected_ledger() {
    let dir = TempDir::new().unwrap();
    write_config(&dir);
    let (token, _) = mint_token_with_limit(&dir, "finite-secret", Some(1)).await;
    let ledger = dir.path().join("token-usage");
    fs::create_dir(&ledger).unwrap();
    fs::set_permissions(&ledger, fs::Permissions::from_mode(0o777)).unwrap();
    let output = admit(&dir, &token, "run").output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("owner-only token usage directory"));

    fs::remove_dir(&ledger).unwrap();
    let redirected = dir.path().join("redirected");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&redirected)
        .unwrap();
    symlink(&redirected, &ledger).unwrap();
    let output = admit(&dir, &token, "run").output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("owner-only token usage directory"));
    assert_eq!(fs::read_dir(redirected).unwrap().count(), 0);
}

#[tokio::test]
async fn corrupt_usage_state_fails_closed_without_echoing_its_contents() {
    let dir = TempDir::new().unwrap();
    write_config(&dir);
    let (token, fingerprint) = mint_token_with_limit(&dir, "finite-secret", Some(1)).await;
    let first = admit(&dir, &token, "run").output().unwrap();
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );

    let contents = br#"{"uses":"contents-must-stay-private","expiresAt":1}"#;
    let state = dir
        .path()
        .join("token-usage")
        .join(format!("{fingerprint}.json"));
    fs::write(&state, contents).unwrap();
    let output = admit(&dir, &token, "run").output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Token usage state") && stderr.contains("is corrupt"));
    assert!(!stderr.contains("contents-must-stay-private"));
    assert_eq!(fs::read(state).unwrap(), contents);
}

#[tokio::test]
async fn dry_run_leaves_budget_unspent_and_failed_launch_spends_it() {
    let dir = TempDir::new().unwrap();
    write_config(&dir);
    let (token, _) = mint_token_with_limit(&dir, "finite-secret", Some(1)).await;
    let plan = run_finite_token(&dir, &token, "run")
        .arg("--dry-run")
        .output()
        .unwrap();
    assert!(
        plan.status.success(),
        "{}",
        String::from_utf8_lossy(&plan.stderr)
    );
    assert!(!dir.path().join("token-usage").exists());

    let failed = run_finite_token(&dir, &token, "run")
        .arg("--")
        .arg(dir.path().join("missing-child"))
        .output()
        .unwrap();
    assert_eq!(failed.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&failed.stderr).contains("Failed to launch command"));
    assert_exhausted(&admit(&dir, &token, "run").output().unwrap(), 1);
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

// ─── --require-presence-at-issuance has nothing to apply to under
// --token (a redeemed token is never minted by `run`) — refuse the
// combination outright as a usage error rather than silently ignoring the
// flag ────

#[test]
fn run_rejects_token_and_require_presence_at_issuance_together_naming_the_conflict() {
    let dir = TempDir::new().unwrap();
    write_config(&dir);

    let output = Command::new(vk_bin())
        .env("VAULTKEEPER_CONFIG_DIR", dir.path())
        .args([
            "run",
            "--token",
            "irrelevant",
            "--require-presence-at-issuance",
            "--",
            "true",
        ])
        .stdin(Stdio::null())
        .output()
        .expect("failed to run");

    assert!(!output.status.success());
    assert_eq!(output.status.code(), Some(2), "clap usage errors exit 2");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--token"), "got: {stderr}");
    assert!(
        stderr.contains("--require-presence-at-issuance"),
        "got: {stderr}"
    );
}

// ─── --dry-run must catch the --set/--as collision the same way a real
// launch does — before this fix, --dry-run rendered cleanly and exited 0
// even though the real launch below refuses ────

#[test]
fn run_token_dry_run_refuses_a_set_as_collision_instead_of_rendering_cleanly() {
    let dir = TempDir::new().unwrap();
    write_config(&dir);

    // No token needs to be minted: the collision is between --as's default
    // (VAULTKEEPER_SECRET) and --set's VAR half, checked against the
    // declared --set overlay entries — never against a resolved value — so
    // it must fire before the token is ever decrypted.
    let output = Command::new(vk_bin())
        .env("VAULTKEEPER_CONFIG_DIR", dir.path())
        .args([
            "run",
            "--token",
            "irrelevant",
            "--dry-run",
            "--set",
            "VAULTKEEPER_SECRET=some-secret",
            "--",
            "true",
        ])
        .stdin(Stdio::null())
        .output()
        .expect("failed to run");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--set"), "got: {stderr}");
    assert!(stderr.contains("--as"), "got: {stderr}");
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains("vaultkeeper run --dry-run"),
        "must refuse instead of rendering a dry-run plan on a colliding --set/--as pair"
    );
}

#[tokio::test]
async fn run_token_real_launch_refuses_a_set_as_collision() {
    let dir = TempDir::new().unwrap();
    write_config(&dir);
    let token = mint_token(&dir, "token-value").await;

    let output = Command::new(vk_bin())
        .env("VAULTKEEPER_CONFIG_DIR", dir.path())
        .args([
            "run",
            "--token",
            &token,
            "--set",
            "VAULTKEEPER_SECRET=some-secret",
            "--",
            "true",
        ])
        .stdin(Stdio::null())
        .output()
        .expect("failed to run");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--set"), "got: {stderr}");
    assert!(stderr.contains("--as"), "got: {stderr}");
}
