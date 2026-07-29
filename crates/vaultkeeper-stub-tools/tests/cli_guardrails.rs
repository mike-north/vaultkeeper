//! Covers the two refusal paths in `cli::run_stub_process` (issue #313
//! guardrail 1) that had zero coverage: the process refuses to do anything
//! (exit 111, useful stderr) both when the test-only sentinel env var is
//! absent, and when it's present but names a behavior table that doesn't
//! exist.
//!
//! Drives the real compiled `vk-stub-secret-tool` binary as a subprocess —
//! via Cargo's `CARGO_BIN_EXE_<name>` integration-test convention, which
//! gives the exact path to the binary Cargo already builds as part of this
//! crate — rather than reimplementing `run_stub_process`'s guardrail checks
//! in-process. Each invocation sets its env only for that one child process
//! (via `Command::env`/`env_remove`), so unlike
//! `crates/vaultkeeper-cli/src/host.rs`'s `stub_tool_secret_tool_ac2` module
//! (which mutates this test process's own `PATH`/env and needs
//! `#[serial]` as a result) these tests never touch the test process's own
//! environment and can run concurrently.

use std::process::Command;

const STUB_BINARY: &str = env!("CARGO_BIN_EXE_vk-stub-secret-tool");

#[test]
fn sentinel_absent_refuses_with_exit_111_and_useful_stderr() {
    let output = Command::new(STUB_BINARY)
        .args(["store", "--label", "x", "--", "vaultkeeper-id", "id"])
        // Guardrail 1: the binary must refuse even if the sentinel simply
        // isn't set in the environment it inherits — explicitly remove it
        // in case the test process's own environment happens to carry it.
        .env_remove("VAULTKEEPER_STUB_TOOLS_SENTINEL")
        .output()
        .expect("failed to spawn vk-stub-secret-tool");

    assert_eq!(
        output.status.code(),
        Some(111),
        "expected exit 111 when the sentinel is absent, got {:?}; stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stdout.is_empty(),
        "a refused run must not emit anything on stdout, got {:?}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("VAULTKEEPER_STUB_TOOLS_SENTINEL") && stderr.contains("refusing to run"),
        "stderr should explain the sentinel is missing and why the process refused, got: {stderr}"
    );
}

#[test]
fn sentinel_present_but_unknown_table_name_refuses_with_exit_111_and_useful_stderr() {
    let output = Command::new(STUB_BINARY)
        .args(["store", "--label", "x", "--", "vaultkeeper-id", "id"])
        .env("VAULTKEEPER_STUB_TOOLS_SENTINEL", "1")
        // No World-path override needed — the process should refuse before
        // ever touching a World.
        .env(
            "VAULTKEEPER_STUB_TOOLS_TABLE_NAME",
            "not-a-real-behavior-table",
        )
        .output()
        .expect("failed to spawn vk-stub-secret-tool");

    assert_eq!(
        output.status.code(),
        Some(111),
        "expected exit 111 for an unknown table name, got {:?}; stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stdout.is_empty(),
        "a refused run must not emit anything on stdout, got {:?}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not-a-real-behavior-table")
            && stderr.contains("no built-in behavior table"),
        "stderr should name the unknown table and explain why the process refused, got: {stderr}"
    );
}
