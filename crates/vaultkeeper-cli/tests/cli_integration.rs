//! Integration tests for the vaultkeeper CLI binary.
//!
//! These tests spawn the compiled `vaultkeeper` binary as a subprocess and
//! verify exit codes, stdout, and stderr — mirroring the TypeScript CLI UATs
//! in `packages/cli-tests/`.
//!
//! Each test uses an isolated temp directory via `VAULTKEEPER_CONFIG_DIR`.

#![allow(deprecated)] // cargo_bin is deprecated but cargo_bin_cmd! macro doesn't return Result

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

/// Create an isolated config environment with a default config.json.
fn cli_test_env() -> (Command, TempDir) {
    let dir = TempDir::new().expect("failed to create temp dir");
    let config = serde_json::json!({
        "version": 1,
        "backends": [{ "type": "file", "enabled": true }],
        "keyRotation": { "gracePeriodDays": 7 },
        "defaults": { "ttlMinutes": 60, "trustTier": "3" }
    });
    let config_path = dir.path().join("config.json");
    fs::write(
        &config_path,
        serde_json::to_string_pretty(&config).unwrap() + "\n",
    )
    .expect("failed to write config");

    let mut cmd = Command::cargo_bin("vaultkeeper").expect("binary not found");
    cmd.env("VAULTKEEPER_CONFIG_DIR", dir.path());
    (cmd, dir)
}

/// Create a command pointing at an isolated (but empty) config dir.
fn cli_test_env_no_config() -> (Command, TempDir) {
    let dir = TempDir::new().expect("failed to create temp dir");
    let mut cmd = Command::cargo_bin("vaultkeeper").expect("binary not found");
    cmd.env("VAULTKEEPER_CONFIG_DIR", dir.path());
    (cmd, dir)
}

// ─── Help and usage ──────────────────────────────────────────────

mod help {
    use super::*;

    #[test]
    fn no_args_prints_help_and_exits_0() {
        let (mut cmd, _dir) = cli_test_env();
        cmd.assert()
            .success()
            .stdout(predicate::str::contains("Usage: vaultkeeper"));
    }

    #[test]
    fn help_flag_prints_help_and_exits_0() {
        let (mut cmd, _dir) = cli_test_env();
        cmd.arg("--help")
            .assert()
            .success()
            .stdout(predicate::str::contains("Usage: vaultkeeper"));
    }

    #[test]
    fn short_help_flag_prints_help_and_exits_0() {
        let (mut cmd, _dir) = cli_test_env();
        cmd.arg("-h")
            .assert()
            .success()
            .stdout(predicate::str::contains("Usage: vaultkeeper"));
    }

    #[test]
    fn lists_all_expected_commands_in_help() {
        let (mut cmd, _dir) = cli_test_env();
        cmd.arg("--help").assert().success().stdout(
            predicate::str::contains("exec")
                .and(predicate::str::contains("doctor"))
                .and(predicate::str::contains("approve"))
                .and(predicate::str::contains("dev-mode"))
                .and(predicate::str::contains("store"))
                .and(predicate::str::contains("delete"))
                .and(predicate::str::contains("config"))
                .and(predicate::str::contains("rotate-key"))
                .and(predicate::str::contains("revoke-key")),
        );
    }

    #[test]
    fn unknown_command_exits_2_with_error() {
        let (mut cmd, _dir) = cli_test_env();
        cmd.arg("not-a-real-command")
            .assert()
            .code(2)
            .stderr(predicate::str::contains("unrecognized subcommand"));
    }

    #[test]
    fn version_flag_prints_version() {
        let (mut cmd, _dir) = cli_test_env();
        cmd.arg("--version")
            .assert()
            .success()
            .stdout(predicate::str::contains("vaultkeeper"));
    }
}

// ─── Doctor command ──────────────────────────────────────────────

mod doctor {
    use super::*;

    #[test]
    fn doctor_runs_and_produces_output() {
        let (mut cmd, _dir) = cli_test_env();
        let output = cmd.arg("doctor").output().expect("failed to run");
        let exit_code = output.status.code().unwrap_or(-1);
        // Doctor may exit 0 (all pass) or 1 (some fail) depending on environment.
        assert!(
            exit_code == 0 || exit_code == 1,
            "expected exit 0 or 1, got {exit_code}"
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        // Output should contain status lines: check markers (✓/✗) or readiness info
        let has_output = stdout.contains('\u{2713}')
            || stdout.contains('\u{2717}')
            || stdout.contains("System ready")
            || stdout.contains("Next steps");
        assert!(has_output, "expected doctor output: {stdout}");
    }
}

// ─── Store and delete lifecycle ──────────────────────────────────

mod store_delete {
    use super::*;

    #[test]
    fn store_exits_1_when_stdin_is_empty() {
        let (mut cmd, _dir) = cli_test_env();
        cmd.args(["store", "--name", "test-secret"])
            .write_stdin("")
            .assert()
            .code(1)
            .stderr(predicate::str::contains("No secret provided on stdin"));
    }

    #[test]
    fn store_succeeds_with_valid_secret() {
        let (mut cmd, _dir) = cli_test_env();
        cmd.args(["store", "--name", "my-key"])
            .write_stdin("super-secret-value")
            .assert()
            .success()
            .stdout(predicate::str::contains(
                "Secret \"my-key\" stored successfully",
            ));
    }

    #[test]
    fn delete_succeeds() {
        let (mut cmd, _dir) = cli_test_env();
        cmd.args(["delete", "--name", "some-key"])
            .assert()
            .success()
            .stdout(predicate::str::contains("Secret \"some-key\" deleted"));
    }
}

// ─── Config command ──────────────────────────────────────────────

mod config {
    use super::*;

    #[test]
    fn config_show_exits_0_and_prints_json() {
        let (mut cmd, _dir) = cli_test_env();
        let output = cmd
            .args(["config", "show"])
            .output()
            .expect("failed to run");
        assert!(output.status.success(), "expected exit 0");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let parsed: serde_json::Value =
            serde_json::from_str(&stdout).expect("stdout should be valid JSON");
        assert_eq!(parsed["version"], 1);
        assert!(parsed["backends"].is_array());
    }

    #[test]
    fn config_init_exits_1_when_config_already_exists() {
        let (mut cmd, _dir) = cli_test_env();
        cmd.args(["config", "init"])
            .assert()
            .code(1)
            .stderr(predicate::str::contains("already exists"));
    }

    #[test]
    fn config_init_creates_config_when_none_exists() {
        let (mut cmd, dir) = cli_test_env_no_config();
        cmd.args(["config", "init"])
            .assert()
            .success()
            .stdout(predicate::str::contains("Config created at"));
        // Verify file was created with valid JSON
        let content =
            fs::read_to_string(dir.path().join("config.json")).expect("config should exist");
        let parsed: serde_json::Value =
            serde_json::from_str(&content).expect("should be valid JSON");
        assert_eq!(parsed["version"], 1);
    }

    #[test]
    fn config_show_exits_1_when_no_config_exists() {
        let (mut cmd, _dir) = cli_test_env_no_config();
        cmd.args(["config", "show"]).assert().code(1);
    }

    #[test]
    fn config_with_no_subcommand_exits_2() {
        let (mut cmd, _dir) = cli_test_env();
        // Clap shows usage info and exits 2 for missing required subcommand
        cmd.arg("config").assert().code(2);
    }
}

// ─── Argument validation ─────────────────────────────────────────

mod argument_validation {
    use super::*;

    #[test]
    fn store_exits_2_when_name_is_missing() {
        let (mut cmd, _dir) = cli_test_env();
        cmd.arg("store")
            .write_stdin("some-secret")
            .assert()
            .code(2)
            .stderr(predicate::str::contains("--name"));
    }

    #[test]
    fn delete_exits_2_when_name_is_missing() {
        let (mut cmd, _dir) = cli_test_env();
        cmd.arg("delete")
            .assert()
            .code(2)
            .stderr(predicate::str::contains("--name"));
    }

    #[test]
    fn exec_exits_2_when_token_is_missing() {
        let (mut cmd, _dir) = cli_test_env();
        cmd.arg("exec")
            .assert()
            .code(2)
            .stderr(predicate::str::contains("--token"));
    }

    #[test]
    fn dev_mode_exits_2_without_required_args() {
        let (mut cmd, _dir) = cli_test_env();
        cmd.arg("dev-mode")
            .assert()
            .code(2)
            .stderr(predicate::str::contains("--path"));
    }

    #[test]
    fn approve_exits_2_without_path() {
        let (mut cmd, _dir) = cli_test_env();
        cmd.arg("approve")
            .assert()
            .code(2)
            .stderr(predicate::str::contains("--path"));
    }
}

// ─── Rotate-key command ──────────────────────────────────────────

mod rotate_key {
    use super::*;

    #[test]
    fn rotate_key_succeeds_with_valid_config() {
        let (mut cmd, _dir) = cli_test_env();
        cmd.arg("rotate-key")
            .assert()
            .success()
            .stdout(predicate::str::contains("Key rotated successfully"));
    }
}

// ─── Revoke-key command ──────────────────────────────────────────

mod revoke_key {
    use super::*;

    #[test]
    fn revoke_key_succeeds_with_valid_config() {
        let (mut cmd, _dir) = cli_test_env();
        cmd.arg("revoke-key")
            .assert()
            .success()
            .stdout(predicate::str::contains("Key revoked successfully"));
    }
}

// ─── Approve command ────────────────────────────────────────────

mod approve {
    use super::*;

    #[test]
    fn approve_succeeds_with_existing_file() {
        let (_, dir) = cli_test_env();

        // Create a file to approve
        let script_path = dir.path().join("test-script.sh");
        std::fs::write(&script_path, "#!/bin/bash\necho hello").unwrap();

        let mut cmd = Command::cargo_bin("vaultkeeper").unwrap();
        cmd.env("VAULTKEEPER_CONFIG_DIR", dir.path())
            .args(["approve", "--path", &script_path.to_string_lossy()])
            .assert()
            .success()
            .stdout(predicate::str::contains("Approved"));
    }

    #[test]
    fn approve_fails_for_nonexistent_file() {
        let (mut cmd, _dir) = cli_test_env();
        cmd.args(["approve", "--path", "/nonexistent/script.sh"])
            .assert()
            .code(1)
            .stderr(predicate::str::contains("Error"));
    }
}

// ─── Dev-mode command ───────────────────────────────────────────

mod dev_mode {
    use super::*;

    #[test]
    fn dev_mode_enable_succeeds() {
        let (mut cmd, _dir) = cli_test_env();
        cmd.args(["dev-mode", "--path", "/usr/bin/test-app", "--enable"])
            .assert()
            .success()
            .stdout(predicate::str::contains("Dev mode enabled"));
    }

    #[test]
    fn dev_mode_disable_succeeds() {
        let (mut cmd, _dir) = cli_test_env();
        // First enable
        cmd.args(["dev-mode", "--path", "/usr/bin/test-app", "--enable"])
            .assert()
            .success();

        // Then disable
        let mut cmd2 = Command::cargo_bin("vaultkeeper").unwrap();
        let dir = _dir; // Reuse same config dir
        cmd2.env("VAULTKEEPER_CONFIG_DIR", dir.path())
            .args(["dev-mode", "--path", "/usr/bin/test-app"])
            .assert()
            .success()
            .stdout(predicate::str::contains("Dev mode disabled"));
    }
}
