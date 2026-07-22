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
                .and(predicate::str::contains("backend"))
                .and(predicate::str::contains("rotate-key"))
                .and(predicate::str::contains("revoke-key"))
                .and(predicate::str::contains("session")),
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

    // Issue #116: a fresh doctor run whose resolved backend is `file` (the
    // post-#98 default) must not show a failing check for an unused plugin
    // backend (ykman/op) — the file backend needs neither. Before the fix,
    // doctor always rendered every non-Ok check with ✗ regardless of
    // whether it was required, so a brand-new file-default install looked
    // broken on the very first command.
    //
    // This asserts specifically on the unused plugin-backend lines, not on
    // overall success/exit code: doctor can legitimately exit 1 (and show a
    // ✗) for a genuinely missing *core* tool like openssl on some hosts, and
    // that's an unrelated, orthogonal failure mode this test must not flake
    // on. The CLI renders each check as `  {icon} {name}...`, so the icon is
    // immediately followed by the check name.
    #[test]
    fn does_not_show_a_failing_check_for_unused_plugin_backends_on_a_fresh_file_default_run() {
        let (mut cmd, _dir) = cli_test_env();
        let output = cmd.arg("doctor").output().expect("failed to run");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            !stdout.contains("\u{2717} ykman"),
            "expected no failing ykman check: {stdout}"
        );
        assert!(
            !stdout.contains("\u{2717} op"),
            "expected no failing op check: {stdout}"
        );
    }

    // Issue #116, acceptance criterion 3: opt-in backends still get their
    // dependency checks when actually configured — the yubikey backend
    // promotes the ykman check back to required, so it's surfaced (most
    // CI/dev machines don't have ykman installed).
    #[test]
    fn surfaces_the_ykman_check_when_the_yubikey_backend_is_configured() {
        let dir = TempDir::new().expect("failed to create temp dir");
        let config = serde_json::json!({
            "version": 1,
            "backends": [{ "type": "yubikey", "enabled": true, "plugin": true }],
            "keyRotation": { "gracePeriodDays": 7 },
            "defaults": { "ttlMinutes": 60, "trustTier": "3" }
        });
        fs::write(
            dir.path().join("config.json"),
            serde_json::to_string_pretty(&config).unwrap() + "\n",
        )
        .expect("failed to write config");

        let mut cmd = Command::cargo_bin("vaultkeeper").expect("binary not found");
        cmd.env("VAULTKEEPER_CONFIG_DIR", dir.path());
        cmd.arg("doctor")
            .assert()
            .stdout(predicate::str::contains("ykman"));
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

    // ─── Presence-per-use enforcement (issue #242) ───────────────
    //
    // The `file` backend never implements `PresenceCapableBackend`, so it is
    // never presence-per-use capable — `--require-presence-per-use` must
    // refuse with a `NotCapable` error before the backend is touched at all.

    #[test]
    fn store_with_require_presence_per_use_refuses_before_touching_backend() {
        let (mut cmd, _dir) = cli_test_env();
        cmd.args(["store", "--name", "api-key", "--require-presence-per-use"])
            .write_stdin("sk-live-abc123")
            .assert()
            .code(1)
            .stderr(predicate::str::contains("active backend ('file')"))
            .stderr(predicate::str::contains("YubiKey"))
            .stderr(predicate::str::contains("1Password"));
    }

    #[test]
    fn store_without_the_flag_is_not_gated() {
        let (mut cmd, _dir) = cli_test_env();
        cmd.args(["store", "--name", "api-key"])
            .write_stdin("sk-live-abc123")
            .assert()
            .success();
    }

    #[test]
    fn delete_with_require_presence_per_use_refuses_before_touching_backend() {
        // Note: this CLI's `delete` is deliberately idempotent for a missing
        // secret (see cmd_delete), so a follow-up unflagged `delete` can't be
        // used as after-the-fact proof the backend was untouched — that
        // guarantee is structural (the presence check runs before
        // `backend.delete()` is ever called) and is covered directly by the
        // `fresh_action_demands` assertions in
        // `crates/vaultkeeper-core/tests/presence_capability.rs`.
        let (mut cmd, _dir) = cli_test_env();
        cmd.args(["delete", "--name", "api-key", "--require-presence-per-use"])
            .assert()
            .code(1)
            .stderr(predicate::str::contains("active backend ('file')"))
            .stderr(predicate::str::contains("YubiKey"))
            .stderr(predicate::str::contains("1Password"));
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
            .stderr(predicate::str::contains("Error: Config already exists at"));
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
    fn config_init_uses_file_backend_on_every_platform() {
        // Regression test for #98 / #235: `config init`'s zero-config default
        // must be the 'file' backend on every platform, never a
        // platform-native keychain/dpapi store.
        let (mut cmd, dir) = cli_test_env_no_config();
        cmd.args(["config", "init"])
            .assert()
            .success()
            .stdout(predicate::str::contains("Config created at"));
        let content =
            fs::read_to_string(dir.path().join("config.json")).expect("config should exist");
        let parsed: serde_json::Value =
            serde_json::from_str(&content).expect("should be valid JSON");
        let backend_type = parsed["backends"][0]["type"].as_str().unwrap_or("");
        assert_eq!(
            backend_type, "file",
            "zero-config default must be 'file' (#98)"
        );
        // The path field must not appear in the generated config — the file backend
        // manages its own storage location and ignores any path in config.
        let backend_obj = parsed["backends"][0]
            .as_object()
            .expect("backend entry should be a JSON object");
        assert!(
            !backend_obj.contains_key("path"),
            "file backend config should not contain a 'path' field"
        );
    }

    #[test]
    fn config_show_exits_1_when_no_config_exists() {
        let (mut cmd, _dir) = cli_test_env_no_config();
        cmd.args(["config", "show"])
            .assert()
            .code(1)
            .stderr(predicate::str::contains(
                "Error: No config file found. Run 'vaultkeeper config init' to create one.",
            ));
    }

    #[test]
    fn config_with_no_subcommand_exits_2() {
        let (mut cmd, _dir) = cli_test_env();
        // Clap shows usage info and exits 2 for missing required subcommand
        cmd.arg("config").assert().code(2);
    }

    // -----------------------------------------------------------------
    // Issue #255: `config init` must create the config directory 0o700
    // (owner-only), matching the TS library's contract.
    // -----------------------------------------------------------------

    /// AC1 + AC3: `config init` creating the config directory from scratch
    /// (a `VAULTKEEPER_CONFIG_DIR` that doesn't exist yet) must leave it
    /// `0o700` on Unix. Skipped on Windows, where POSIX mode bits don't
    /// apply.
    #[test]
    #[cfg(unix)]
    fn config_init_creates_fresh_config_dir_as_0700() {
        use std::os::unix::fs::PermissionsExt;

        let parent = TempDir::new().expect("failed to create temp dir");
        let config_dir = parent.path().join("vk-config");
        assert!(!config_dir.exists(), "config dir must not pre-exist");

        let mut cmd = Command::cargo_bin("vaultkeeper").expect("binary not found");
        cmd.env("VAULTKEEPER_CONFIG_DIR", &config_dir);
        cmd.args(["config", "init"])
            .assert()
            .success()
            .stdout(predicate::str::contains("Config created at"));

        let mode = fs::metadata(&config_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o700,
            "freshly created config dir must be 0o700, got {mode:o}"
        );
    }

    /// AC2: if the config directory already exists with broader
    /// permissions, `config init` must leave those permissions untouched —
    /// no chmod-on-startup surprise.
    #[test]
    #[cfg(unix)]
    fn config_init_leaves_existing_wider_permission_dir_untouched() {
        use std::os::unix::fs::PermissionsExt;

        let parent = TempDir::new().expect("failed to create temp dir");
        let config_dir = parent.path().join("vk-config");
        fs::create_dir(&config_dir).unwrap();
        fs::set_permissions(&config_dir, fs::Permissions::from_mode(0o755)).unwrap();

        let mut cmd = Command::cargo_bin("vaultkeeper").expect("binary not found");
        cmd.env("VAULTKEEPER_CONFIG_DIR", &config_dir);
        cmd.args(["config", "init"]).assert().success();

        let mode = fs::metadata(&config_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o755,
            "pre-existing config dir permissions must be left untouched"
        );
    }

    /// AC3 on non-Unix: `config init` still creates the directory (mode
    /// bits are a Unix-only concept, so there's nothing to assert there).
    #[test]
    #[cfg(not(unix))]
    fn config_init_creates_fresh_config_dir_on_non_unix() {
        let parent = TempDir::new().expect("failed to create temp dir");
        let config_dir = parent.path().join("vk-config");
        assert!(!config_dir.exists(), "config dir must not pre-exist");

        let mut cmd = Command::cargo_bin("vaultkeeper").expect("binary not found");
        cmd.env("VAULTKEEPER_CONFIG_DIR", &config_dir);
        cmd.args(["config", "init"])
            .assert()
            .success()
            .stdout(predicate::str::contains("Config created at"));

        assert!(config_dir.is_dir());
    }
}

// ─── Backend capabilities command (issue #262) ────────────────────

mod backend_capabilities {
    use super::*;

    #[test]
    fn capabilities_exits_0_and_reports_file_backend_as_not_presence_capable() {
        // Exact match, not a substring check: the Rust CLI reports exactly
        // one row (the active/configured `file` backend — there is no
        // config-driven multi-backend registry wired into the CLI), so its
        // own output is fully deterministic. This pins the Rust CLI's own
        // output byte-for-byte; it is not a claim that this string equals
        // the TS CLI's output, which enumerates every registered backend
        // type (six rows) — see the PR description for the byte-diff
        // evidence of that difference.
        let (mut cmd, _dir) = cli_test_env();
        cmd.args(["backend", "capabilities"])
            .assert()
            .success()
            .stdout(predicate::eq(
                "Backend capabilities (per configured instance):\n\n  file  Encrypted File Store  presence-per-use: no\n\nA backend with presence-per-use: yes forces a distinct, fresh human action\nper operation and can satisfy `--require-presence-per-use`.\n",
            ));
    }

    #[test]
    fn capabilities_json_emits_a_row_with_type_display_name_and_presence_per_use() {
        let (mut cmd, _dir) = cli_test_env();
        let output = cmd
            .args(["backend", "capabilities", "--json"])
            .output()
            .expect("failed to run");
        assert!(output.status.success(), "expected exit 0");
        // Assert on the real bytes rather than `from_utf8_lossy`, which would
        // silently replace any invalid byte with U+FFFD and let a real
        // encoding/serialization bug in the CLI's output pass unnoticed.
        let stdout = String::from_utf8(output.stdout).expect("stdout should be valid UTF-8");
        // Byte-exact pin, deliberately order-sensitive: the row struct's
        // field declaration order must keep matching the TS CLI's
        // (`type`, `displayName`, `presencePerUse`). A parse-then-compare
        // assertion alone would keep passing if the serialization ever
        // regressed to serde_json's alphabetical map order.
        assert_eq!(
            stdout,
            "[\n  {\n    \"type\": \"file\",\n    \"displayName\": \"Encrypted File Store\",\n    \"presencePerUse\": false\n  }\n]\n",
        );
        let parsed: serde_json::Value =
            serde_json::from_str(&stdout).expect("stdout should be valid JSON");
        let rows = parsed.as_array().expect("expected a JSON array");
        assert!(!rows.is_empty(), "expected at least one row");
        let file_row = rows
            .iter()
            .find(|r| r["type"] == "file")
            .expect("expected a 'file' backend row");
        assert_eq!(file_row["displayName"], "Encrypted File Store");
        assert_eq!(file_row["presencePerUse"], false);
    }

    #[test]
    fn capabilities_works_without_a_config_file() {
        // Discovery must be available before any config exists, mirroring
        // that `store`/`delete` refusal (--require-presence-per-use) is
        // meant to be checkable ahead of time.
        //
        // The command is intentionally config-independent today: it always
        // reports the hardcoded active `FileBackend`, the same way every
        // other command does (see PR #266 discussion) — so the row content
        // here matches `capabilities_json_emits_a_row_with_type_display_name_and_presence_per_use`
        // exactly, config file or not.
        let (mut cmd, _dir) = cli_test_env_no_config();
        let output = cmd
            .args(["backend", "capabilities", "--json"])
            .output()
            .expect("failed to run");
        assert!(output.status.success(), "expected exit 0");
        let stdout = String::from_utf8(output.stdout).expect("stdout should be valid UTF-8");
        let parsed: serde_json::Value =
            serde_json::from_str(&stdout).expect("stdout should be valid JSON");
        let rows = parsed.as_array().expect("expected a JSON array");
        assert!(!rows.is_empty(), "expected at least one row");
        let file_row = rows
            .iter()
            .find(|r| r["type"] == "file")
            .expect("expected a 'file' backend row");
        assert_eq!(file_row["displayName"], "Encrypted File Store");
        assert_eq!(file_row["presencePerUse"], false);
    }

    #[test]
    fn backend_with_no_subcommand_exits_2() {
        let (mut cmd, _dir) = cli_test_env();
        cmd.arg("backend").assert().code(2);
    }

    #[test]
    fn backend_help_documents_capabilities_subcommand() {
        let (mut cmd, _dir) = cli_test_env();
        cmd.args(["backend", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("capabilities"));
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

    /// Issue #238, AC5: key state persists to the config dir, so the
    /// grace-period guard survives across processes. Each `Command::cargo_bin`
    /// call here is a fresh OS process sharing only the config dir — before
    /// persistence, the second process would start with no in-memory previous
    /// key and rotate again successfully instead of rejecting.
    #[test]
    fn second_rotate_rejects_while_grace_period_is_active_across_processes() {
        let (mut first, dir) = cli_test_env();
        first
            .arg("rotate-key")
            .assert()
            .success()
            .stdout(predicate::str::contains("Key rotated successfully"));

        let mut second = Command::cargo_bin("vaultkeeper").expect("binary not found");
        second.env("VAULTKEEPER_CONFIG_DIR", dir.path());
        second
            .arg("rotate-key")
            .assert()
            .failure()
            .stderr(predicate::str::contains("rotation is already in progress"));
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

// ─── Profile command (issue #277) ───────────────────────────────

mod profile {
    use super::*;

    fn write_profile(dir: &TempDir, name: &str, json: &serde_json::Value) {
        let profiles_dir = dir.path().join("profiles");
        fs::create_dir_all(&profiles_dir).expect("failed to create profiles dir");
        fs::write(
            profiles_dir.join(format!("{name}.json")),
            serde_json::to_string_pretty(json).unwrap(),
        )
        .expect("failed to write profile");
    }

    #[test]
    fn init_creates_a_loadable_profile() {
        let (mut cmd, dir) = cli_test_env();
        cmd.args(["profile", "init", "my-profile"])
            .assert()
            .success()
            .stdout(predicate::str::contains("Profile created at"));

        let content = fs::read_to_string(dir.path().join("profiles").join("my-profile.json"))
            .expect("profile file should exist");
        let parsed: serde_json::Value =
            serde_json::from_str(&content).expect("should be valid JSON");
        assert_eq!(parsed["name"], "my-profile");
        assert_eq!(parsed["version"], 1);
    }

    #[test]
    fn init_exits_1_when_profile_already_exists() {
        let (mut cmd, dir) = cli_test_env();
        write_profile(
            &dir,
            "my-profile",
            &serde_json::json!({ "version": 1, "name": "my-profile", "entries": {} }),
        );
        cmd.args(["profile", "init", "my-profile"])
            .assert()
            .code(1)
            .stderr(predicate::str::contains("already exists"));
    }

    #[test]
    fn list_reports_no_profiles_when_none_exist() {
        let (mut cmd, _dir) = cli_test_env();
        cmd.args(["profile", "list"])
            .assert()
            .success()
            .stdout(predicate::str::contains("(no profiles)"));
    }

    #[test]
    fn list_reports_created_profile_names() {
        let (mut cmd, dir) = cli_test_env();
        write_profile(
            &dir,
            "github-mcp",
            &serde_json::json!({ "version": 1, "name": "github-mcp", "entries": {} }),
        );
        cmd.args(["profile", "list"])
            .assert()
            .success()
            .stdout(predicate::eq("github-mcp\n"));
    }

    #[test]
    fn show_exits_1_when_profile_does_not_exist() {
        let (mut cmd, _dir) = cli_test_env();
        cmd.args(["profile", "show", "does-not-exist"])
            .assert()
            .code(1)
            .stderr(predicate::str::contains("No profile found"));
    }

    #[test]
    fn show_reports_shape_and_never_the_stored_secret_value() {
        // AC5 (UAT): plant a known sentinel secret value reachable from the
        // profile, then grep the FULL command output for its absence.
        const SENTINEL: &str = "sk-live-VERY-SECRET-SENTINEL-VALUE-0xdeadbeef";

        let (mut store_cmd, dir) = cli_test_env();
        store_cmd
            .args(["store", "--name", "github-pat"])
            .write_stdin(SENTINEL)
            .assert()
            .success();

        write_profile(
            &dir,
            "github-mcp",
            &serde_json::json!({
                "version": 1,
                "name": "github-mcp",
                "entries": {
                    "GITHUB_TOKEN": {
                        "secret": "github-pat",
                        "materialize": "secret",
                        "minTrust": "registry"
                    }
                }
            }),
        );

        let mut show_cmd = Command::cargo_bin("vaultkeeper").unwrap();
        let output = show_cmd
            .env("VAULTKEEPER_CONFIG_DIR", dir.path())
            .args(["profile", "show", "github-mcp"])
            .output()
            .expect("failed to run");
        let stdout = String::from_utf8(output.stdout).expect("stdout should be valid UTF-8");
        let stderr = String::from_utf8(output.stderr).expect("stderr should be valid UTF-8");

        assert!(output.status.success(), "expected exit 0: {stderr}");
        assert!(
            stdout.contains("GITHUB_TOKEN"),
            "expected entry name in output: {stdout}"
        );
        assert!(
            stdout.contains("github-pat"),
            "the secret *name* is safe to print: {stdout}"
        );
        assert!(
            !stdout.contains(SENTINEL) && !stderr.contains(SENTINEL),
            "show must never print the secret value: stdout={stdout} stderr={stderr}"
        );
    }

    #[test]
    fn lint_reports_shape_and_never_the_stored_secret_value() {
        // AC5 (UAT), lint half of the same requirement.
        const SENTINEL: &str = "sk-live-ANOTHER-SECRET-SENTINEL-0xfeedface";

        let (mut store_cmd, dir) = cli_test_env();
        store_cmd
            .args(["store", "--name", "github-pat"])
            .write_stdin(SENTINEL)
            .assert()
            .success();

        write_profile(
            &dir,
            "github-mcp",
            &serde_json::json!({
                "version": 1,
                "name": "github-mcp",
                "entries": {
                    "GITHUB_TOKEN": {
                        "secret": "github-pat",
                        "materialize": "secret",
                        "minTrust": "unverified",
                        "requirePresencePerUse": false
                    }
                }
            }),
        );

        let mut lint_cmd = Command::cargo_bin("vaultkeeper").unwrap();
        let output = lint_cmd
            .env("VAULTKEEPER_CONFIG_DIR", dir.path())
            .args(["profile", "lint", "github-mcp"])
            .output()
            .expect("failed to run");
        let stdout = String::from_utf8(output.stdout).expect("stdout should be valid UTF-8");
        let stderr = String::from_utf8(output.stderr).expect("stderr should be valid UTF-8");

        assert!(output.status.success(), "expected exit 0: {stderr}");
        assert!(
            stdout.contains("schema OK"),
            "expected schema-OK line: {stdout}"
        );
        assert!(
            stdout.contains("per-machine") && stdout.contains("per-repository"),
            "expected the per-machine/per-repository caveat: {stdout}"
        );
        // The config.json default trustTier ("3" == Dev/unverified in this
        // test env) matches the profile's "unverified" minTrust exactly, so
        // no loosening warning is expected here — this test is about the
        // secret-value guarantee, not the warning logic (covered by Rust
        // unit tests in crates/vaultkeeper-core/src/profile/lint.rs).
        assert!(
            !stdout.contains(SENTINEL) && !stderr.contains(SENTINEL),
            "lint must never print the secret value: stdout={stdout} stderr={stderr}"
        );
    }

    #[test]
    fn show_and_lint_reject_a_profile_that_violates_a_load_time_invariant() {
        let (mut cmd, dir) = cli_test_env();
        write_profile(
            &dir,
            "broken",
            &serde_json::json!({
                "version": 1,
                "name": "broken",
                "entries": {
                    "K": { "signingKey": "sk", "materialize": "secret" }
                }
            }),
        );
        cmd.args(["profile", "show", "broken"])
            .assert()
            .code(1)
            .stderr(predicate::str::contains("materialize"));
    }

    #[test]
    fn profile_with_no_subcommand_exits_2() {
        let (mut cmd, _dir) = cli_test_env();
        cmd.arg("profile").assert().code(2);
    }

    // --- Security anchor: profile-name validation (review follow-up) ---

    #[test]
    fn init_rejects_a_parent_directory_traversal_name_and_writes_nothing_outside_profiles() {
        let (mut cmd, dir) = cli_test_env();
        cmd.args(["profile", "init", "../evil"])
            .assert()
            .code(1)
            .stderr(predicate::str::contains("Error"));

        // Nothing was written outside (or even inside) profiles/ — the
        // rejection must happen before any path construction, let alone a
        // file write.
        assert!(
            !dir.path().parent().unwrap().join("evil.json").exists(),
            "must not have written a file outside the temp config dir"
        );
        let profiles_dir = dir.path().join("profiles");
        if profiles_dir.exists() {
            let remaining: Vec<_> = fs::read_dir(&profiles_dir)
                .expect("failed to read profiles dir")
                .collect();
            assert!(
                remaining.is_empty(),
                "profiles dir must be empty after a rejected hostile name"
            );
        }
    }

    #[test]
    fn init_rejects_a_bare_path_separator_name() {
        let (mut cmd, _dir) = cli_test_env();
        cmd.args(["profile", "init", "a/b"])
            .assert()
            .code(1)
            .stderr(predicate::str::contains("Error"));
    }

    #[test]
    fn show_rejects_a_parent_directory_traversal_name() {
        let (mut cmd, _dir) = cli_test_env();
        cmd.args(["profile", "show", "../../../etc/passwd"])
            .assert()
            .code(1)
            .stderr(predicate::str::contains("Error"));
    }

    // --- CLI usage: NAME and --profile-file are mutually exclusive ---

    #[test]
    fn show_with_both_name_and_profile_file_is_a_usage_error() {
        let (mut cmd, dir) = cli_test_env();
        write_profile(
            &dir,
            "github-mcp",
            &serde_json::json!({ "version": 1, "name": "github-mcp", "entries": {} }),
        );
        let profile_file_path = dir.path().join("profiles").join("github-mcp.json");
        cmd.args([
            "profile",
            "show",
            "foo",
            "--profile-file",
            &profile_file_path.to_string_lossy(),
        ])
        .assert()
        .code(2);
    }

    #[test]
    fn lint_with_both_name_and_profile_file_is_a_usage_error() {
        let (mut cmd, dir) = cli_test_env();
        write_profile(
            &dir,
            "github-mcp",
            &serde_json::json!({ "version": 1, "name": "github-mcp", "entries": {} }),
        );
        let profile_file_path = dir.path().join("profiles").join("github-mcp.json");
        cmd.args([
            "profile",
            "lint",
            "foo",
            "--profile-file",
            &profile_file_path.to_string_lossy(),
        ])
        .assert()
        .code(2);
    }

    #[test]
    fn show_with_neither_name_nor_profile_file_is_a_usage_error() {
        let (mut cmd, _dir) = cli_test_env();
        cmd.args(["profile", "show"]).assert().code(2);
    }

    #[test]
    fn show_loads_via_profile_file_without_a_name() {
        let (mut cmd, dir) = cli_test_env();
        write_profile(
            &dir,
            "github-mcp",
            &serde_json::json!({ "version": 1, "name": "github-mcp", "entries": {} }),
        );
        let profile_file_path = dir.path().join("profiles").join("github-mcp.json");
        cmd.args([
            "profile",
            "show",
            "--profile-file",
            &profile_file_path.to_string_lossy(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("github-mcp"));
    }

    // --- `profile lint` warnings: advisory-only, always exits 0 ---

    #[test]
    fn lint_reports_warnings_on_stdout_and_still_exits_0() {
        // cli_test_env's config.json default trustTier is "3" (unverified);
        // an entry requesting "sigstore" is *stronger*, not weaker, so no
        // minTrust warning fires from that axis. useLimit absent and
        // requirePresencePerUse absent (defaults to false) both loosen
        // relative to LintBaseline::default() (useLimit: 1,
        // requirePresencePerUse: true), which is enough to trigger warnings
        // without needing a weaker minTrust.
        let (mut cmd, dir) = cli_test_env();
        write_profile(
            &dir,
            "loose",
            &serde_json::json!({
                "version": 1,
                "name": "loose",
                "entries": {
                    "K": {
                        "secret": "s",
                        "materialize": "secret",
                        "minTrust": "sigstore"
                    }
                }
            }),
        );
        cmd.args(["profile", "lint", "loose"])
            .assert()
            .success()
            .stdout(predicate::str::contains("Policy-loosening warnings"))
            .stdout(predicate::str::contains("useLimit"))
            .stdout(predicate::str::contains("requirePresencePerUse"));
    }

    // --- File mode: profiles are owner-only (0o600), matching config.json ---

    #[cfg(unix)]
    #[test]
    fn init_writes_the_profile_file_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let (mut cmd, dir) = cli_test_env();
        cmd.args(["profile", "init", "my-profile"])
            .assert()
            .success();

        let path = dir.path().join("profiles").join("my-profile.json");
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "profile file must be owner-only (0o600)");
    }
}

// ─── Session revoke command (issue #298) ─────────────────────────
//
// Deep enforcement semantics (jti/kgen checks, tamper/rollback/deletion
// fail-closed, read-modify-write vs. rotateKey/revokeKey, cross-process
// persistence) are proven at the `vaultkeeper-core` layer in
// `crates/vaultkeeper-core/tests/lease_revocation_integration.rs`, using the
// same "independent instances sharing only a backing store" technique this
// codebase already uses for process-boundary testing (see
// `crates/vaultkeeper-core/src/keys/storage.rs`'s own cross-process doc and
// its `save_then_load_round_trips_*` tests) — there is no `vaultkeeper
// session check`/`sign` command yet to drive that enforcement through a real
// subprocess. These tests instead cover the CLI surface itself: argument
// parsing, exit codes, and that the command actually persists state to
// `keys.enc` rather than crashing or silently no-op'ing.

mod session {
    use super::*;

    #[test]
    fn revoke_by_jti_succeeds() {
        let (mut cmd, _dir) = cli_test_env();
        cmd.args(["session", "revoke", "--jti", "some-jti-001"])
            .assert()
            .success()
            .stdout(predicate::str::contains("Lease some-jti-001 revoked"));
    }

    #[test]
    fn revoke_by_key_succeeds() {
        let (mut cmd, _dir) = cli_test_env();
        cmd.args(["session", "revoke", "--key", "release-signer"])
            .assert()
            .success()
            .stdout(predicate::str::contains(
                "Every outstanding lease for key \"release-signer\" revoked",
            ));
    }

    #[test]
    fn revoke_with_neither_jti_nor_key_is_a_usage_error() {
        let (mut cmd, _dir) = cli_test_env();
        cmd.args(["session", "revoke"])
            .assert()
            .code(1)
            .stderr(predicate::str::contains("exactly one of --jti or --key"));
    }

    #[test]
    fn revoke_with_both_jti_and_key_is_a_clap_usage_error() {
        let (mut cmd, _dir) = cli_test_env();
        cmd.args([
            "session",
            "revoke",
            "--jti",
            "some-jti",
            "--key",
            "release-signer",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("cannot be used with"));
    }

    #[test]
    fn session_with_no_subcommand_exits_2() {
        let (mut cmd, _dir) = cli_test_env();
        cmd.arg("session").assert().code(2);
    }

    /// A `session revoke` actually persists `keys.enc` to the config dir —
    /// not a silent in-memory-only no-op — and a second, independent
    /// subprocess invocation against the same config dir (the cross-process
    /// case) succeeds too, i.e. it reads back whatever the first process
    /// wrote via the same read-modify-write path rather than erroring on it.
    #[test]
    fn revoke_persists_and_a_second_process_can_revoke_again() {
        let (mut first, dir) = cli_test_env();
        first
            .args(["session", "revoke", "--jti", "cross-process-jti"])
            .assert()
            .success();

        assert!(
            dir.path().join("keys.enc").exists(),
            "session revoke must persist keys.enc"
        );

        let mut second = Command::cargo_bin("vaultkeeper").expect("binary not found");
        second.env("VAULTKEEPER_CONFIG_DIR", dir.path());
        second
            .args(["session", "revoke", "--key", "release-signer"])
            .assert()
            .success();

        // rotate-key afterwards must still succeed — a corrupt read-modify-write
        // merge in either revoke call would otherwise leave keys.enc unreadable.
        let mut third = Command::cargo_bin("vaultkeeper").expect("binary not found");
        third.env("VAULTKEEPER_CONFIG_DIR", dir.path());
        third
            .arg("rotate-key")
            .assert()
            .success()
            .stdout(predicate::str::contains("Key rotated successfully"));
    }

    #[test]
    fn session_help_documents_revoke_subcommand() {
        let (mut cmd, _dir) = cli_test_env();
        cmd.args(["session", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("revoke"));
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
