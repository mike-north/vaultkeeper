//! Conformance test runner for the native Rust CLI binary.
//!
//! Exercises the compiled `vaultkeeper` binary against the data-driven
//! conformance cases defined in `vaultkeeper-conformance`.
//!
//! Each test case runs in an isolated temp directory with its own
//! `VAULTKEEPER_CONFIG_DIR`.

use std::fs;
use std::io::Write;
use std::process::Command;
use tempfile::TempDir;
use vaultkeeper_conformance::{all_cases, matches_output, ConformanceCase};

/// Find the vaultkeeper binary built by cargo.
fn vaultkeeper_bin() -> std::path::PathBuf {
    // When running via `cargo test`, CARGO_BIN_EXE_vaultkeeper may be set
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_vaultkeeper") {
        return std::path::PathBuf::from(path);
    }
    // Fall back to finding it relative to target dir
    let mut path = std::env::current_exe()
        .expect("can't find current exe")
        .parent()
        .expect("no parent dir")
        .parent()
        .expect("no grandparent dir")
        .to_path_buf();
    path.push("vaultkeeper");
    path
}

/// Default config JSON matching the TypeScript CLI's test config.
fn default_config_json() -> String {
    serde_json::to_string_pretty(&serde_json::json!({
        "version": 1,
        "backends": [{ "type": "file", "enabled": true }],
        "keyRotation": { "gracePeriodDays": 7 },
        "defaults": { "ttlMinutes": 60, "trustTier": "3" }
    }))
    .unwrap()
        + "\n"
}

/// Run a single conformance case and return a detailed error message on failure.
fn run_case(case: &ConformanceCase, bin: &std::path::Path) -> Result<(), String> {
    let dir = TempDir::new().map_err(|e| format!("failed to create temp dir: {e}"))?;

    if case.needs_config {
        let config_path = dir.path().join("config.json");
        fs::write(&config_path, default_config_json())
            .map_err(|e| format!("failed to write config: {e}"))?;
    }

    let mut cmd = Command::new(bin);
    cmd.args(&case.command);
    cmd.env("VAULTKEEPER_CONFIG_DIR", dir.path());

    if let Some(ref stdin_data) = case.stdin {
        cmd.stdin(std::process::Stdio::piped());
        let mut child = cmd
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| format!("failed to spawn: {e}"))?;

        if let Some(ref mut stdin) = child.stdin {
            stdin
                .write_all(stdin_data.as_bytes())
                .map_err(|e| format!("failed to write stdin: {e}"))?;
        }
        // Drop stdin to close it
        drop(child.stdin.take());

        let output = child
            .wait_with_output()
            .map_err(|e| format!("failed to wait: {e}"))?;

        check_output(case, &output)
    } else {
        cmd.stdin(std::process::Stdio::null());
        let output = cmd.output().map_err(|e| format!("failed to run: {e}"))?;
        check_output(case, &output)
    }
}

fn check_output(case: &ConformanceCase, output: &std::process::Output) -> Result<(), String> {
    let exit_code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    let mut errors = Vec::new();

    // Check exit code (-1 means don't check)
    if case.expected_exit_code != -1 && exit_code != case.expected_exit_code {
        errors.push(format!(
            "exit code: expected {}, got {}",
            case.expected_exit_code, exit_code
        ));
    }

    if !matches_output(&case.expected_stdout, &stdout) {
        errors.push(format!(
            "stdout mismatch: expected {:?}, got {:?}",
            case.expected_stdout,
            stdout.chars().take(200).collect::<String>()
        ));
    }

    if !matches_output(&case.expected_stderr, &stderr) {
        errors.push(format!(
            "stderr mismatch: expected {:?}, got {:?}",
            case.expected_stderr,
            stderr.chars().take(200).collect::<String>()
        ));
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "Case '{}' failed:\n  {}\n  stdout={:?}\n  stderr={:?}\n  exit={}",
            case.name,
            errors.join("\n  "),
            stdout.chars().take(300).collect::<String>(),
            stderr.chars().take(300).collect::<String>(),
            exit_code
        ))
    }
}

#[test]
fn all_conformance_cases_pass() {
    let bin = vaultkeeper_bin();
    assert!(
        bin.exists(),
        "vaultkeeper binary not found at {}",
        bin.display()
    );

    let cases = all_cases();
    let mut failures = Vec::new();

    for case in &cases {
        if let Err(msg) = run_case(case, &bin) {
            failures.push(msg);
        }
    }

    if !failures.is_empty() {
        panic!(
            "{} of {} conformance cases failed:\n\n{}",
            failures.len(),
            cases.len(),
            failures.join("\n\n")
        );
    }
}
