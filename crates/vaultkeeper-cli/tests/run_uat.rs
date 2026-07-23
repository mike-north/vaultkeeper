//! User-acceptance tests for `vaultkeeper run` (issue #279).
//!
//! These exercise the real subprocess paths end to end — the compiled
//! `vaultkeeper` binary launching a real child process — never a mocked or
//! hand-built approximation of stdio/signal behavior. Each test maps
//! directly to one of the issue's acceptance criteria (noted per test).
//!
//! `sh`, `cat`, and `kill` are assumed present (this file is unix-only —
//! CI only runs the native CLI on ubuntu/macos, see `.github/workflows/ci.yml`).

#![cfg(unix)]

use std::fs;
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use tempfile::TempDir;

/// The compiled `vaultkeeper` binary, set by cargo for integration tests.
fn vk_bin() -> &'static str {
    env!("CARGO_BIN_EXE_vaultkeeper")
}

/// An isolated `$VAULTKEEPER_CONFIG_DIR` with a `file`-backend config and one
/// profile declaring a single `materialize: "secret"` entry (`GREETING` →
/// the secret named `greeting`). Every UAT here uses the `file` backend —
/// the only backend the native CLI's real operations support today — which
/// is also exactly what makes AC2's degradation notice fire deterministically.
fn run_test_env(profile_json: &serde_json::Value) -> TempDir {
    let dir = TempDir::new().expect("failed to create temp dir");
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

    let profiles_dir = dir.path().join("profiles");
    fs::create_dir_all(&profiles_dir).expect("failed to create profiles dir");
    fs::write(
        profiles_dir.join("uat.json"),
        serde_json::to_string_pretty(profile_json).unwrap(),
    )
    .expect("failed to write profile");

    dir
}

/// Store a secret in the isolated config dir via the real `store` command
/// (never hand-writing the backend's on-disk file — that would be an
/// approximation of the real storage contract, not the contract itself).
fn store_secret(dir: &TempDir, name: &str, value: &str) {
    let mut child = Command::new(vk_bin())
        .env("VAULTKEEPER_CONFIG_DIR", dir.path())
        .args(["store", "--name", name])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn store");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(value.as_bytes())
        .unwrap();
    let status = child.wait().expect("store did not exit");
    assert!(status.success(), "store must succeed");
}

fn single_secret_profile() -> serde_json::Value {
    serde_json::json!({
        "version": 1,
        "name": "uat",
        "entries": {
            "GREETING": { "secret": "greeting", "materialize": "secret" }
        }
    })
}

fn empty_profile() -> serde_json::Value {
    serde_json::json!({ "version": 1, "name": "uat", "entries": {} })
}

// ─── AC1: stdio round trip — byte-exact, both directions ─────────

#[test]
fn ac1_stdio_round_trip_is_byte_exact_through_a_framed_message_style_payload() {
    let dir = run_test_env(&empty_profile());

    // A framed-message-shaped payload (Content-Length header + body, as an
    // MCP stdio transport would send), including a null byte and a
    // non-UTF8-safe byte sequence, to prove this is a true byte-exact
    // passthrough and not a line-oriented text approximation.
    let mut payload = Vec::new();
    payload.extend_from_slice(b"Content-Length: 21\r\n\r\n");
    payload.extend_from_slice(b"{\"jsonrpc\":\"2.0\"}\r\n\x00");
    payload.extend_from_slice(&[0xff, 0x00, 0x01, 0x02, 0x03]);

    let mut child = Command::new(vk_bin())
        .env("VAULTKEEPER_CONFIG_DIR", dir.path())
        .args(["run", "--profile", "uat", "--", "cat"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn run");

    child
        .stdin
        .take()
        .unwrap()
        .write_all(&payload)
        .expect("failed to write stdin");
    // `cat` doesn't exit until stdin closes.

    let output = child.wait_with_output().expect("run did not exit");
    assert!(output.status.success());
    assert_eq!(
        output.stdout, payload,
        "run's stdout must be byte-exact identical to what was written to \
         stdin — no added buffering, no injected bytes, in either direction"
    );
}

// ─── AC2: stdout purity — child's bytes only, notice on stderr ───

#[test]
fn ac2_stdout_contains_exactly_the_childs_bytes_and_the_degradation_notice_is_stderr_only() {
    let dir = run_test_env(&single_secret_profile());
    store_secret(&dir, "greeting", "the-real-secret-value");

    // A known, exact byte sequence the child writes — deliberately including
    // bytes a naive implementation might mangle (embedded newlines, no
    // trailing newline).
    let known_bytes = b"KNOWN-BYTES-\x01\x02-NO-TRAILING-NEWLINE";

    let output = Command::new(vk_bin())
        .env("VAULTKEEPER_CONFIG_DIR", dir.path())
        .args([
            "run",
            "--profile",
            "uat",
            "--",
            "sh",
            "-c",
            &format!("printf '%s' '{}'", String::from_utf8_lossy(known_bytes)),
        ])
        .stdin(Stdio::null())
        .output()
        .expect("failed to run");

    assert!(output.status.success());
    assert_eq!(
        output.stdout,
        known_bytes.to_vec(),
        "stdout must contain EXACTLY the child's bytes — no vaultkeeper \
         diagnostic may appear on stdout while a child runs"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("every entry in this run resolved through the file backend"),
        "the file-only degradation notice must appear on stderr, got: {stderr}"
    );
    // The secret value itself must never leak into a vaultkeeper diagnostic.
    assert!(!stderr.contains("the-real-secret-value"));
}

// ─── AC3: signals reach the child; the wrapper outlives it ───────

/// Send `signal` (e.g. `"-TERM"`, `"-INT"`) to `pid` via the real `kill(1)`
/// utility — deliberately not `Child::kill()` (SIGKILL only) — so the test
/// exercises the same signal delivery path an MCP client terminating the
/// wrapper directly would use.
fn send_signal(pid: u32, signal: &str) {
    let status = Command::new("kill")
        .args([signal, &pid.to_string()])
        .status()
        .expect("failed to invoke kill(1)");
    assert!(status.success(), "kill {signal} {pid} must succeed");
}

fn wait_for_file(path: &std::path::Path, timeout: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if path.exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

#[test]
fn ac3_sigterm_reaches_the_child_and_the_wrapper_outlives_it() {
    let dir = run_test_env(&empty_profile());
    let marker = dir.path().join("terminated.marker");

    // A child that traps SIGTERM, records that it was reached, and exits —
    // proving both halves of AC3: the signal reached the child (the marker
    // file), and the wrapper did not exit before the child did (asserted
    // below via the wrapper's own successful, non-timed-out wait).
    let child_script = dir.path().join("trap_term.sh");
    fs::write(
        &child_script,
        format!(
            "#!/bin/sh\ntrap 'echo reached > {}; exit 0' TERM\nsleep 30 &\nwait $!\n",
            marker.display()
        ),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&child_script, fs::Permissions::from_mode(0o755)).unwrap();
    }

    let mut wrapper = Command::new(vk_bin())
        .env("VAULTKEEPER_CONFIG_DIR", dir.path())
        .args([
            "run",
            "--profile",
            "uat",
            "--",
            child_script.to_str().unwrap(),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn run");

    // Give the wrapper time to actually spawn the child and install its
    // signal handlers before sending SIGTERM.
    std::thread::sleep(Duration::from_millis(300));
    send_signal(wrapper.id(), "-TERM");

    let status = wrapper.wait().expect("wrapper never exited");
    assert!(
        status.success(),
        "the child trapped SIGTERM and exited 0 itself, so the wrapper must \
         propagate that same exit status, not a signal-death code"
    );
    assert!(
        wait_for_file(&marker, Duration::from_secs(1)),
        "the forwarded SIGTERM must have reached the child (marker file \
         never appeared)"
    );
}

#[test]
fn ac3_sigint_reaches_the_child_and_the_wrapper_outlives_it() {
    let dir = run_test_env(&empty_profile());
    let marker = dir.path().join("interrupted.marker");

    let child_script = dir.path().join("trap_int.sh");
    fs::write(
        &child_script,
        format!(
            "#!/bin/sh\ntrap 'echo reached > {}; exit 0' INT\nsleep 30 &\nwait $!\n",
            marker.display()
        ),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&child_script, fs::Permissions::from_mode(0o755)).unwrap();
    }

    let mut wrapper = Command::new(vk_bin())
        .env("VAULTKEEPER_CONFIG_DIR", dir.path())
        .args([
            "run",
            "--profile",
            "uat",
            "--",
            child_script.to_str().unwrap(),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn run");

    std::thread::sleep(Duration::from_millis(300));
    send_signal(wrapper.id(), "-INT");

    let status = wrapper.wait().expect("wrapper never exited");
    assert!(status.success());
    assert!(
        wait_for_file(&marker, Duration::from_secs(1)),
        "the forwarded SIGINT must have reached the child (marker file \
         never appeared)"
    );
}

// ─── AC4: exit semantics ──────────────────────────────────────────

#[test]
fn ac4_child_exit_code_is_propagated() {
    let dir = run_test_env(&empty_profile());
    let status = Command::new(vk_bin())
        .env("VAULTKEEPER_CONFIG_DIR", dir.path())
        .args(["run", "--profile", "uat", "--", "sh", "-c", "exit 7"])
        .stdin(Stdio::null())
        .status()
        .expect("failed to run");
    assert_eq!(status.code(), Some(7));
}

#[test]
fn ac4_a_signal_killed_child_yields_128_plus_n() {
    let dir = run_test_env(&empty_profile());
    // No trap — the default action for SIGTERM is to terminate the process,
    // so `sleep 30` sent a real SIGTERM below dies by signal, not by its own
    // `exit()`.
    let mut wrapper = Command::new(vk_bin())
        .env("VAULTKEEPER_CONFIG_DIR", dir.path())
        .args(["run", "--profile", "uat", "--", "sleep", "30"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn run");

    std::thread::sleep(Duration::from_millis(300));
    send_signal(wrapper.id(), "-TERM");

    let status = wrapper.wait().expect("wrapper never exited");
    assert_eq!(
        status.code(),
        Some(128 + 15),
        "SIGTERM is signal 15 — a signal-killed child must yield exit code \
         128+15=143"
    );
}

#[test]
fn ac4_child_closing_stdout_early_still_exits_cleanly_with_no_epipe_trace() {
    let dir = run_test_env(&empty_profile());
    let output = Command::new(vk_bin())
        .env("VAULTKEEPER_CONFIG_DIR", dir.path())
        .args([
            "run",
            "--profile",
            "uat",
            "--",
            "sh",
            "-c",
            // Close its own stdout, keep running briefly, then exit 0 —
            // must not be treated as an error by the wrapper.
            "exec 1>&-; sleep 0.1; exit 0",
        ])
        .stdin(Stdio::null())
        .output()
        .expect("failed to run");

    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.to_lowercase().contains("panic"),
        "no panic/stack trace on a child closing stdout early, got: {stderr}"
    );
    assert!(
        !stderr.to_lowercase().contains("epipe"),
        "EPIPE must never surface as an error here, got: {stderr}"
    );
}

// ─── AC5: --dry-run is plan-only ──────────────────────────────────

#[test]
fn ac5_dry_run_prints_plan_and_never_mints_or_launches() {
    let dir = run_test_env(&serde_json::json!({
        "version": 1,
        "name": "uat",
        "entries": {
            "GREETING": {
                "secret": "greeting", "materialize": "secret"
            },
            "LEASE_ENTRY": {
                "secret": "greeting", "materialize": "lease",
                "minTrust": "unverified", "ttlSeconds": 900
            }
        }
    }));
    store_secret(&dir, "greeting", "must-never-appear-in-dry-run-output");

    let marker = dir.path().join("launched.marker");
    let output = Command::new(vk_bin())
        .env("VAULTKEEPER_CONFIG_DIR", dir.path())
        .args([
            "run",
            "--profile",
            "uat",
            "--set",
            "ADHOC=greeting",
            "--dry-run",
            "--",
            "sh",
            "-c",
            &format!("touch {}", marker.display()),
        ])
        .stdin(Stdio::null())
        .output()
        .expect("failed to run");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Every declared var, its rung, and its backend.
    assert!(stdout.contains("GREETING"));
    assert!(stdout.contains("rung:        2 (secret)"));
    assert!(stdout.contains("LEASE_ENTRY"));
    assert!(stdout.contains("rung:        3 (lease)"));
    assert!(stdout.contains("backend:     file"));

    // The --set entry is marked UNREVIEWED.
    assert!(stdout.contains("ADHOC"));
    assert!(stdout.contains("UNREVIEWED"));

    // No value ever appears.
    assert!(!stdout.contains("must-never-appear-in-dry-run-output"));

    // Nothing was launched.
    assert!(
        !marker.exists(),
        "--dry-run must exit without launching the command"
    );
}

#[test]
fn ac5_dry_run_never_mints_a_rung_3_lease_even_when_backend_would_otherwise_refuse() {
    // A lease entry whose minTrust requires an executable hash `run` does
    // not yet supply (see the PR description) would be REFUSED by a real
    // (non-dry-run) resolution. --dry-run must never attempt resolution at
    // all, so this must succeed and print the plan regardless.
    let dir = run_test_env(&serde_json::json!({
        "version": 1,
        "name": "uat",
        "entries": {
            "ELEVATED": {
                "secret": "greeting", "materialize": "lease", "minTrust": "sigstore"
            }
        }
    }));

    let output = Command::new(vk_bin())
        .env("VAULTKEEPER_CONFIG_DIR", dir.path())
        .args(["run", "--profile", "uat", "--dry-run"])
        .stdin(Stdio::null())
        .output()
        .expect("failed to run");

    assert!(
        output.status.success(),
        "dry-run must never attempt to mint, so it cannot hit the \
         executable-trust refusal a real run of this same profile would"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("ELEVATED"));
    assert!(stdout.contains("minTrust:    sigstore"));
}

// ─── Flag surface / validation ────────────────────────────────────

#[test]
fn run_requires_profile_or_profile_file() {
    let dir = run_test_env(&empty_profile());
    let output = Command::new(vk_bin())
        .env("VAULTKEEPER_CONFIG_DIR", dir.path())
        .args(["run", "--", "true"])
        .stdin(Stdio::null())
        .output()
        .expect("failed to run");
    assert!(!output.status.success());
}

#[test]
fn run_rejects_profile_and_profile_file_together() {
    let dir = run_test_env(&empty_profile());
    let output = Command::new(vk_bin())
        .env("VAULTKEEPER_CONFIG_DIR", dir.path())
        .args([
            "run",
            "--profile",
            "uat",
            "--profile-file",
            "/tmp/whatever.json",
            "--",
            "true",
        ])
        .stdin(Stdio::null())
        .output()
        .expect("failed to run");
    assert!(!output.status.success());
}

#[test]
fn run_rejects_a_malformed_set_flag() {
    let dir = run_test_env(&empty_profile());
    let output = Command::new(vk_bin())
        .env("VAULTKEEPER_CONFIG_DIR", dir.path())
        .args(["run", "--profile", "uat", "--set", "NOEQUALS", "--", "true"])
        .stdin(Stdio::null())
        .output()
        .expect("failed to run");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--set"));
}

#[test]
fn run_help_documents_the_exact_require_presence_at_mint_flag_name() {
    let dir = run_test_env(&empty_profile());
    let mut child = Command::new(vk_bin())
        .env("VAULTKEEPER_CONFIG_DIR", dir.path())
        .args(["run", "--help"])
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
        stdout.contains("--require-presence-at-mint"),
        "help text must use the exact scope-suffixed flag name, got: {stdout}"
    );
    assert!(
        !stdout.contains("--require-presence <"),
        "must never be spelled as the bare/per-use --require-presence form"
    );
}
