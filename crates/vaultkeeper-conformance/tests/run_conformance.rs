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
use vaultkeeper_conformance::{ConformanceCase, all_cases, matches_output};

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
    path.push(format!("vaultkeeper{}", std::env::consts::EXE_SUFFIX));
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

/// Reject any `extra_files` path that isn't made up entirely of plain,
/// relative name components — i.e. every [`std::path::Component`] must be
/// `Normal`, so absolute paths, `.` and `..` segments, an empty path, and
/// Windows path prefixes/root-dirs are all rejected — so a
/// malicious/malformed conformance case can never write outside the case's
/// isolated temp directory.
fn validate_extra_file_path(rel_path: &str) -> Result<(), String> {
    let components: Vec<_> = std::path::Path::new(rel_path).components().collect();
    let is_safe_relative = !components.is_empty()
        && components
            .iter()
            .all(|c| matches!(c, std::path::Component::Normal(_)));
    if is_safe_relative {
        Ok(())
    } else {
        Err(format!(
            "extra_files path {rel_path:?} must be relative and contain no '.', '..', or empty \
             path segments"
        ))
    }
}

/// Run a single conformance case and return a detailed error message on failure.
fn run_case(case: &ConformanceCase, bin: &std::path::Path) -> Result<(), String> {
    let dir = TempDir::new().map_err(|e| format!("failed to create temp dir: {e}"))?;
    let config_path = dir.path().join("config.json");

    if case.needs_config {
        fs::write(&config_path, default_config_json())
            .map_err(|e| format!("failed to write config: {e}"))?;
    }

    for (rel_path, content) in &case.extra_files {
        validate_extra_file_path(rel_path).map_err(|e| format!("case '{}': {e}", case.name))?;

        let path = dir.path().join(rel_path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("failed to create dir for extra file {rel_path}: {e}"))?;
        }
        fs::write(&path, content)
            .map_err(|e| format!("failed to write extra file {rel_path}: {e}"))?;
    }

    // Substitute __SELF_BINARY__ with the actual vaultkeeper binary path
    let args: Vec<String> = case
        .command
        .iter()
        .map(|arg| {
            if arg == "__SELF_BINARY__" {
                bin.to_string_lossy().into_owned()
            } else {
                arg.clone()
            }
        })
        .collect();

    let mut cmd = Command::new(bin);
    cmd.args(&args);
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

        check_output(case, &output, &config_path)
    } else {
        cmd.stdin(std::process::Stdio::null());
        let output = cmd.output().map_err(|e| format!("failed to run: {e}"))?;
        check_output(case, &output, &config_path)
    }
}

fn check_output(
    case: &ConformanceCase,
    output: &std::process::Output,
    config_path: &std::path::Path,
) -> Result<(), String> {
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

    if let Some(ref matcher) = case.expected_config_file {
        match fs::read_to_string(config_path) {
            Ok(content) => {
                if !matches_output(matcher, &content) {
                    errors.push(format!(
                        "config file mismatch: expected {matcher:?}, got {:?}",
                        content.chars().take(300).collect::<String>()
                    ));
                }
            }
            Err(e) => {
                errors.push(format!("failed to read config file: {e}"));
            }
        }
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

#[cfg(test)]
mod extra_file_path_validation_tests {
    use super::validate_extra_file_path;

    #[test]
    fn accepts_a_plain_relative_path() {
        assert!(validate_extra_file_path("profiles/empty-profile.json").is_ok());
    }

    #[test]
    fn rejects_an_absolute_path() {
        assert!(validate_extra_file_path("/etc/passwd").is_err());
    }

    #[test]
    fn rejects_a_parent_directory_traversal() {
        assert!(validate_extra_file_path("../../etc/passwd").is_err());
    }

    #[test]
    fn rejects_a_parent_directory_component_in_the_middle_of_the_path() {
        assert!(validate_extra_file_path("profiles/../../escape.json").is_err());
    }

    #[test]
    fn rejects_an_empty_path() {
        assert!(validate_extra_file_path("").is_err());
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
