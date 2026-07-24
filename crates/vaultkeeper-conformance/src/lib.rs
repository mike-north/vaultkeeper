//! Conformance test definitions for vaultkeeper.
//!
//! Defines data-driven test cases that both the native Rust CLI and the npm
//! WASM CLI must pass identically. Cases are serializable to JSON so the JS
//! conformance runner can load them.
//!
//! See [`backend_cases`] for a second, narrower corpus scoped to
//! backend-level (not CLI-level) behavior, applicable to any `SecretBackend`
//! implementation — including the TS `InMemoryBackend` test double and the
//! Rust core `InMemoryBackend` (issue #312).

pub mod backend_cases;

use serde::{Deserialize, Serialize};

/// How to match expected output.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
pub enum OutputMatcher {
    /// Exact string match.
    Exact(String),
    /// Output must contain this substring.
    Contains(String),
    /// Output must match this regex pattern.
    Regex(String),
    /// Output must parse as JSON containing these keys.
    JsonContains(serde_json::Value),
    /// Any output is acceptable.
    Any,
}

/// A single conformance test case.
///
/// # Preprocessing
///
/// The literal `__SELF_BINARY__` in `command` args is a placeholder that each
/// test runner must replace with the real path to the vaultkeeper binary before
/// execution. This allows the `approve` command (which hashes an executable) to
/// target a file that is guaranteed to exist.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConformanceCase {
    /// Human-readable test name.
    pub name: String,
    /// CLI arguments (e.g. `["doctor"]` or `["store", "--name", "mykey"]`).
    ///
    /// May contain the sentinel `__SELF_BINARY__` — see struct-level docs.
    pub command: Vec<String>,
    /// Optional stdin content.
    pub stdin: Option<String>,
    /// Whether this test needs a config.json in the config dir.
    pub needs_config: bool,
    /// Expected exit code. Use `-1` to skip the exit-code assertion (e.g. when
    /// the command may legitimately exit 0 or 1 depending on environment).
    pub expected_exit_code: i32,
    /// Expected stdout pattern.
    pub expected_stdout: OutputMatcher,
    /// Expected stderr pattern.
    pub expected_stderr: OutputMatcher,
    /// Optional check against the contents of `config.json` in the config
    /// dir after the command runs. `None` skips the check. Used for cases
    /// that must assert on persisted config content rather than stdout/stderr
    /// (e.g. verifying the zero-config default backend written by `config
    /// init` — see #98 / #235).
    #[serde(default)]
    pub expected_config_file: Option<OutputMatcher>,
    /// Additional files to write under the isolated config dir before
    /// running, as `(path relative to the config dir, content)` pairs.
    /// Parent directories are created as needed. Used for cases that need a
    /// real on-disk fixture beyond `config.json` — e.g. a `run`/`profile`
    /// case that needs a loadable `profiles/<name>.json` (issue #279).
    #[serde(default)]
    pub extra_files: Vec<(String, String)>,
}

// ─── Help and usage cases ────────────────────────────────────────

fn help_cases() -> Vec<ConformanceCase> {
    vec![
        ConformanceCase {
            name: "no args prints help and exits 0".into(),
            command: vec![],
            stdin: None,
            needs_config: false,
            expected_exit_code: 0,
            expected_stdout: OutputMatcher::Contains("vaultkeeper".into()),
            expected_stderr: OutputMatcher::Any,
            expected_config_file: None,
            extra_files: Vec::new(),
        },
        ConformanceCase {
            name: "help flag prints help and exits 0".into(),
            command: vec!["--help".into()],
            stdin: None,
            needs_config: false,
            expected_exit_code: 0,
            expected_stdout: OutputMatcher::Contains("vaultkeeper".into()),
            expected_stderr: OutputMatcher::Any,
            expected_config_file: None,
            extra_files: Vec::new(),
        },
        ConformanceCase {
            name: "short help flag prints help and exits 0".into(),
            command: vec!["-h".into()],
            stdin: None,
            needs_config: false,
            expected_exit_code: 0,
            expected_stdout: OutputMatcher::Contains("vaultkeeper".into()),
            expected_stderr: OutputMatcher::Any,
            expected_config_file: None,
            extra_files: Vec::new(),
        },
        ConformanceCase {
            name: "version flag prints version".into(),
            command: vec!["--version".into()],
            stdin: None,
            needs_config: false,
            expected_exit_code: 0,
            expected_stdout: OutputMatcher::Contains("vaultkeeper".into()),
            expected_stderr: OutputMatcher::Any,
            expected_config_file: None,
            extra_files: Vec::new(),
        },
        ConformanceCase {
            name: "help lists all expected commands".into(),
            command: vec!["--help".into()],
            stdin: None,
            needs_config: false,
            expected_exit_code: 0,
            expected_stdout: OutputMatcher::Regex(
                "(?s)run.*doctor.*approve.*dev-mode.*store.*delete.*config.*rotate-key.*revoke-key"
                    .into(),
            ),
            expected_stderr: OutputMatcher::Any,
            expected_config_file: None,
            extra_files: Vec::new(),
        },
    ]
}

// ─── Unknown command cases ───────────────────────────────────────

fn error_cases() -> Vec<ConformanceCase> {
    vec![ConformanceCase {
        name: "unknown command exits with error".into(),
        command: vec!["nonexistent-command".into()],
        stdin: None,
        needs_config: false,
        expected_exit_code: 2,
        expected_stdout: OutputMatcher::Any,
        expected_stderr: OutputMatcher::Contains("error".into()),
        expected_config_file: None,
        extra_files: Vec::new(),
    }]
}

// ─── Argument validation cases ───────────────────────────────────

fn argument_validation_cases() -> Vec<ConformanceCase> {
    vec![
        ConformanceCase {
            name: "store requires --name".into(),
            command: vec!["store".into()],
            stdin: Some("some-secret".into()),
            needs_config: false,
            expected_exit_code: 2,
            expected_stdout: OutputMatcher::Any,
            expected_stderr: OutputMatcher::Contains("--name".into()),
            expected_config_file: None,
            extra_files: Vec::new(),
        },
        ConformanceCase {
            name: "delete requires --name".into(),
            command: vec!["delete".into()],
            stdin: None,
            needs_config: false,
            expected_exit_code: 2,
            expected_stdout: OutputMatcher::Any,
            expected_stderr: OutputMatcher::Contains("--name".into()),
            expected_config_file: None,
            extra_files: Vec::new(),
        },
        ConformanceCase {
            name: "exec requires --token".into(),
            command: vec!["exec".into()],
            stdin: None,
            needs_config: false,
            expected_exit_code: 2,
            expected_stdout: OutputMatcher::Any,
            expected_stderr: OutputMatcher::Contains("--token".into()),
            expected_config_file: None,
            extra_files: Vec::new(),
        },
        ConformanceCase {
            name: "approve requires --path".into(),
            command: vec!["approve".into()],
            stdin: None,
            needs_config: false,
            expected_exit_code: 2,
            expected_stdout: OutputMatcher::Any,
            expected_stderr: OutputMatcher::Contains("--path".into()),
            expected_config_file: None,
            extra_files: Vec::new(),
        },
        ConformanceCase {
            name: "dev-mode requires --path".into(),
            command: vec!["dev-mode".into()],
            stdin: None,
            needs_config: false,
            expected_exit_code: 2,
            expected_stdout: OutputMatcher::Any,
            expected_stderr: OutputMatcher::Contains("--path".into()),
            expected_config_file: None,
            extra_files: Vec::new(),
        },
        ConformanceCase {
            name: "config with no subcommand exits 2".into(),
            command: vec!["config".into()],
            stdin: None,
            needs_config: false,
            expected_exit_code: 2,
            expected_stdout: OutputMatcher::Any,
            expected_stderr: OutputMatcher::Any,
            expected_config_file: None,
            extra_files: Vec::new(),
        },
    ]
}

// ─── Store/delete cases ──────────────────────────────────────────

fn store_delete_cases() -> Vec<ConformanceCase> {
    vec![
        ConformanceCase {
            name: "store succeeds with valid secret".into(),
            command: vec!["store".into(), "--name".into(), "conformance-key".into()],
            stdin: Some("conformance-secret".into()),
            needs_config: true,
            expected_exit_code: 0,
            expected_stdout: OutputMatcher::Contains("stored successfully".into()),
            expected_stderr: OutputMatcher::Any,
            expected_config_file: None,
            extra_files: Vec::new(),
        },
        ConformanceCase {
            name: "store exits 1 when stdin is empty".into(),
            command: vec!["store".into(), "--name".into(), "empty-key".into()],
            stdin: Some(String::new()),
            needs_config: true,
            expected_exit_code: 1,
            expected_stdout: OutputMatcher::Any,
            expected_stderr: OutputMatcher::Contains("No secret provided".into()),
            expected_config_file: None,
            extra_files: Vec::new(),
        },
        ConformanceCase {
            name: "delete succeeds".into(),
            command: vec!["delete".into(), "--name".into(), "some-key".into()],
            stdin: None,
            needs_config: true,
            expected_exit_code: 0,
            expected_stdout: OutputMatcher::Contains("deleted".into()),
            expected_stderr: OutputMatcher::Any,
            expected_config_file: None,
            extra_files: Vec::new(),
        },
    ]
}

// ─── Config cases ────────────────────────────────────────────────

fn config_cases() -> Vec<ConformanceCase> {
    vec![
        ConformanceCase {
            // Regression coverage for #98 / #235: in a fresh, config-less
            // environment the zero-config default written to disk must be
            // the 'file' backend on every platform, never a platform-native
            // keychain/dpapi store.
            name: "config init writes the 'file' backend as the zero-config default (#98)".into(),
            command: vec!["config".into(), "init".into()],
            stdin: None,
            needs_config: false,
            expected_exit_code: 0,
            expected_stdout: OutputMatcher::Contains("created".into()),
            expected_stderr: OutputMatcher::Any,
            expected_config_file: Some(OutputMatcher::JsonContains(serde_json::json!({
                "backends": [{ "type": "file" }]
            }))),
            extra_files: Vec::new(),
        },
        ConformanceCase {
            name: "config show outputs valid JSON with version".into(),
            command: vec!["config".into(), "show".into()],
            stdin: None,
            needs_config: true,
            expected_exit_code: 0,
            expected_stdout: OutputMatcher::Contains("\"version\"".into()),
            expected_stderr: OutputMatcher::Any,
            expected_config_file: None,
            extra_files: Vec::new(),
        },
        ConformanceCase {
            name: "config show exits 1 when no config exists".into(),
            command: vec!["config".into(), "show".into()],
            stdin: None,
            needs_config: false,
            expected_exit_code: 1,
            expected_stdout: OutputMatcher::Any,
            expected_stderr: OutputMatcher::Contains(
                "Error: No config file found. Run 'vaultkeeper config init' to create one.".into(),
            ),
            expected_config_file: None,
            extra_files: Vec::new(),
        },
        ConformanceCase {
            name: "config init exits 1 when config already exists".into(),
            command: vec!["config".into(), "init".into()],
            stdin: None,
            needs_config: true,
            expected_exit_code: 1,
            expected_stdout: OutputMatcher::Any,
            expected_stderr: OutputMatcher::Contains("Error: Config already exists at".into()),
            expected_config_file: None,
            extra_files: Vec::new(),
        },
    ]
}

// ─── Doctor cases ────────────────────────────────────────────────

fn doctor_cases() -> Vec<ConformanceCase> {
    vec![ConformanceCase {
        name: "doctor produces output".into(),
        command: vec!["doctor".into()],
        stdin: None,
        needs_config: false,
        // Doctor may exit 0 or 1 depending on environment
        expected_exit_code: -1, // -1 = don't check exit code
        expected_stdout: OutputMatcher::Any,
        expected_stderr: OutputMatcher::Any,
        expected_config_file: None,
        extra_files: Vec::new(),
    }]
}

// ─── Rotate-key cases ────────────────────────────────────────────

fn rotate_key_cases() -> Vec<ConformanceCase> {
    vec![ConformanceCase {
        name: "rotate-key succeeds with valid config".into(),
        command: vec!["rotate-key".into()],
        stdin: None,
        needs_config: true,
        expected_exit_code: 0,
        expected_stdout: OutputMatcher::Contains("rotated successfully".into()),
        expected_stderr: OutputMatcher::Any,
        expected_config_file: None,
        extra_files: Vec::new(),
    }]
}

// ─── Approve cases ──────────────────────────────────────────────

fn approve_cases() -> Vec<ConformanceCase> {
    vec![ConformanceCase {
        name: "approve succeeds for existing file".into(),
        command: vec![
            "approve".into(),
            "--path".into(),
            // Use vaultkeeper binary itself as the target — it always exists
            "__SELF_BINARY__".into(),
        ],
        stdin: None,
        needs_config: true,
        expected_exit_code: 0,
        expected_stdout: OutputMatcher::Contains("Approved".into()),
        expected_stderr: OutputMatcher::Any,
        expected_config_file: None,
        extra_files: Vec::new(),
    }]
}

// ─── Dev-mode cases ─────────────────────────────────────────────

fn dev_mode_cases() -> Vec<ConformanceCase> {
    vec![
        ConformanceCase {
            name: "dev-mode enable succeeds".into(),
            command: vec![
                "dev-mode".into(),
                "--path".into(),
                "/tmp/test-script.sh".into(),
                "--enable".into(),
            ],
            stdin: None,
            needs_config: true,
            expected_exit_code: 0,
            expected_stdout: OutputMatcher::Contains("enabled".into()),
            expected_stderr: OutputMatcher::Any,
            expected_config_file: None,
            extra_files: Vec::new(),
        },
        ConformanceCase {
            name: "dev-mode disable succeeds".into(),
            command: vec![
                "dev-mode".into(),
                "--path".into(),
                "/tmp/test-script.sh".into(),
            ],
            stdin: None,
            needs_config: true,
            expected_exit_code: 0,
            expected_stdout: OutputMatcher::Contains("disabled".into()),
            expected_stderr: OutputMatcher::Any,
            expected_config_file: None,
            extra_files: Vec::new(),
        },
    ]
}

// ─── Backend capabilities cases (issue #262) ─────────────────────

fn backend_capabilities_cases() -> Vec<ConformanceCase> {
    vec![
        ConformanceCase {
            name:
                "backend capabilities exits 0 and reports the file backend as not presence-capable"
                    .into(),
            command: vec!["backend".into(), "capabilities".into()],
            stdin: None,
            // `backend capabilities` is a preflight discovery step (issue
            // #262) — it must work before any config.json exists, so it can
            // be checked before `store`/`delete --require-presence-per-use`.
            // Verified empirically: the file backend is always available
            // without configuration, so no config is needed here.
            needs_config: false,
            expected_exit_code: 0,
            // Exact match, not a loose regex: the Rust CLI reports exactly one
            // row (the active/configured backend — there is no config-driven
            // multi-backend registry wired into the CLI), so its own output is
            // fully deterministic and worth pinning byte-for-byte. This is
            // Rust-CLI-self-consistency coverage, not a claim that this string
            // equals the TS CLI's output — the TS CLI enumerates every
            // registered backend type (six rows) and its raw stdout differs
            // from this (see PR description for the byte-diff evidence).
            expected_stdout: OutputMatcher::Exact(
                "Backend capabilities (per configured instance):\n\n  file  Encrypted File Store  presence-per-use: no\n\nA backend with presence-per-use: yes forces a distinct, fresh human action\nper operation and can satisfy `--require-presence-per-use`.\n".into(),
            ),
            expected_stderr: OutputMatcher::Any,
            expected_config_file: None,
            extra_files: Vec::new(),
        },
        ConformanceCase {
            name: "backend capabilities --json emits a row with type, displayName, presencePerUse"
                .into(),
            command: vec!["backend".into(), "capabilities".into(), "--json".into()],
            stdin: None,
            // Same discovery-step rationale as the text-mode case above.
            needs_config: false,
            expected_exit_code: 0,
            expected_stdout: OutputMatcher::JsonContains(serde_json::json!([{
                "type": "file",
                "displayName": "Encrypted File Store",
                "presencePerUse": false
            }])),
            expected_stderr: OutputMatcher::Any,
            expected_config_file: None,
            extra_files: Vec::new(),
        },
        ConformanceCase {
            name: "backend with no subcommand exits 2".into(),
            command: vec!["backend".into()],
            stdin: None,
            needs_config: false,
            expected_exit_code: 2,
            expected_stdout: OutputMatcher::Any,
            expected_stderr: OutputMatcher::Any,
            expected_config_file: None,
            extra_files: Vec::new(),
        },
    ]
}

// ─── Run cases (issue #279) ───────────────────────────────────────
//
// These exercise the `run` CLI surface's flag semantics/validation only —
// exact conformance coverage of the same kind `argument_validation_cases`
// already provides for `exec`/`store`/`delete`/etc. `run`'s stdio/signal
// behavior is exercised by real-subprocess UATs in
// `crates/vaultkeeper-cli/tests/run_uat.rs` (this harness's `stdin`-only,
// no-pty `Command::output()` model isn't the right layer for signal
// forwarding or byte-exact fd-inheritance assertions).

fn run_cases() -> Vec<ConformanceCase> {
    vec![
        ConformanceCase {
            name: "run requires --profile or --profile-file".into(),
            command: vec!["run".into(), "--".into(), "true".into()],
            stdin: None,
            needs_config: false,
            expected_exit_code: 2,
            expected_stdout: OutputMatcher::Any,
            expected_stderr: OutputMatcher::Contains("--profile".into()),
            expected_config_file: None,
            extra_files: Vec::new(),
        },
        ConformanceCase {
            name: "run rejects --profile and --profile-file together".into(),
            command: vec![
                "run".into(),
                "--profile".into(),
                "x".into(),
                "--profile-file".into(),
                "/tmp/x.json".into(),
                "--".into(),
                "true".into(),
            ],
            stdin: None,
            needs_config: false,
            expected_exit_code: 2,
            expected_stdout: OutputMatcher::Any,
            expected_stderr: OutputMatcher::Any,
            expected_config_file: None,
            extra_files: Vec::new(),
        },
        ConformanceCase {
            name: "run rejects a --set value with no '='".into(),
            command: vec![
                "run".into(),
                "--profile".into(),
                "nonexistent".into(),
                "--set".into(),
                "NOEQUALS".into(),
                "--".into(),
                "true".into(),
            ],
            stdin: None,
            needs_config: true,
            expected_exit_code: 1,
            expected_stdout: OutputMatcher::Any,
            expected_stderr: OutputMatcher::Contains("--set".into()),
            expected_config_file: None,
            extra_files: Vec::new(),
        },
        ConformanceCase {
            // Renamed from a previous version of this case that claimed to
            // test the "no command specified" path but actually only
            // exercised profile lookup (the "No profile found" branch runs
            // first) — see the two cases below for genuine coverage of the
            // no-command branch against a profile that actually loads.
            name: "run exits 1 with 'No profile found' for a nonexistent profile".into(),
            command: vec![
                "run".into(),
                "--profile".into(),
                "nonexistent-profile".into(),
            ],
            stdin: None,
            needs_config: true,
            expected_exit_code: 1,
            expected_stdout: OutputMatcher::Any,
            expected_stderr: OutputMatcher::Contains("No profile found".into()),
            expected_config_file: None,
            extra_files: Vec::new(),
        },
        ConformanceCase {
            // Genuine coverage of the "No command specified" branch: a real,
            // loadable profile (via `extra_files`) with no trailing command
            // and no `--dry-run` — `command.is_empty()` must fire, not the
            // profile-lookup error above.
            name: "run exits 1 with 'No command specified' for a valid profile and no command"
                .into(),
            command: vec!["run".into(), "--profile".into(), "empty-profile".into()],
            stdin: None,
            needs_config: true,
            expected_exit_code: 1,
            expected_stdout: OutputMatcher::Any,
            expected_stderr: OutputMatcher::Contains("No command specified".into()),
            expected_config_file: None,
            extra_files: vec![(
                "profiles/empty-profile.json".into(),
                r#"{ "version": 1, "name": "empty-profile", "entries": {} }"#.into(),
            )],
        },
        ConformanceCase {
            // `--dry-run` against that same real profile is plan-only and
            // needs no trailing command at all.
            name: "run --dry-run against a valid profile prints the plan and exits 0".into(),
            command: vec![
                "run".into(),
                "--profile".into(),
                "empty-profile".into(),
                "--dry-run".into(),
            ],
            stdin: None,
            needs_config: true,
            expected_exit_code: 0,
            expected_stdout: OutputMatcher::Contains("plan only".into()),
            expected_stderr: OutputMatcher::Any,
            expected_config_file: None,
            extra_files: vec![(
                "profiles/empty-profile.json".into(),
                r#"{ "version": 1, "name": "empty-profile", "entries": {} }"#.into(),
            )],
        },
        ConformanceCase {
            // The security-relevant refusal path (issue #279, owner-adjudicated
            // correction): a real, non-dry-run invocation with
            // --require-presence-at-issuance set must refuse outright, never
            // proceed silently or with a mere warning.
            name: "run refuses a real launch when --require-presence-at-issuance is set".into(),
            command: vec![
                "run".into(),
                "--profile".into(),
                "empty-profile".into(),
                "--require-presence-at-issuance".into(),
                "--".into(),
                "true".into(),
            ],
            stdin: None,
            needs_config: true,
            expected_exit_code: 1,
            expected_stdout: OutputMatcher::Any,
            expected_stderr: OutputMatcher::Contains("not yet enforced".into()),
            expected_config_file: None,
            extra_files: vec![(
                "profiles/empty-profile.json".into(),
                r#"{ "version": 1, "name": "empty-profile", "entries": {} }"#.into(),
            )],
        },
        ConformanceCase {
            name: "run --help documents the exact --require-presence-at-issuance flag name".into(),
            command: vec!["run".into(), "--help".into()],
            stdin: None,
            needs_config: false,
            expected_exit_code: 0,
            expected_stdout: OutputMatcher::Contains("--require-presence-at-issuance".into()),
            expected_stderr: OutputMatcher::Any,
            expected_config_file: None,
            extra_files: Vec::new(),
        },
        // ─── run --token (issue #333: exec folded into run) ───────
        //
        // Positive redemption requires a real, freshly-minted JWE bound to
        // this test's own key material — not something a static,
        // stdin/argv-only conformance case can produce — so that coverage
        // lives in the real-subprocess UATs
        // (`crates/vaultkeeper-cli/tests/run_token_uat.rs`). These cases
        // cover the flag-validation surface only, the same scope
        // `argument_validation_cases`'s "exec requires --token" already
        // established for the predecessor verb.
        ConformanceCase {
            name: "run --token conflicts with --profile, naming both flags".into(),
            command: vec![
                "run".into(),
                "--profile".into(),
                "x".into(),
                "--token".into(),
                "y".into(),
                "--".into(),
                "true".into(),
            ],
            stdin: None,
            needs_config: false,
            expected_exit_code: 2,
            expected_stdout: OutputMatcher::Any,
            expected_stderr: OutputMatcher::Contains("--profile".into()),
            expected_config_file: None,
            extra_files: Vec::new(),
        },
        ConformanceCase {
            name: "run --token conflicts with --profile-file, naming both flags".into(),
            command: vec![
                "run".into(),
                "--profile-file".into(),
                "/tmp/x.json".into(),
                "--token".into(),
                "y".into(),
                "--".into(),
                "true".into(),
            ],
            stdin: None,
            needs_config: false,
            expected_exit_code: 2,
            expected_stdout: OutputMatcher::Any,
            expected_stderr: OutputMatcher::Contains("--profile-file".into()),
            expected_config_file: None,
            extra_files: Vec::new(),
        },
        ConformanceCase {
            name: "run --token rejects an invalid --as var name with a typed error".into(),
            command: vec![
                "run".into(),
                "--token".into(),
                "irrelevant".into(),
                "--as".into(),
                "lower_case".into(),
                "--".into(),
                "true".into(),
            ],
            stdin: None,
            needs_config: true,
            expected_exit_code: 1,
            expected_stdout: OutputMatcher::Any,
            expected_stderr: OutputMatcher::Contains("--as".into()),
            expected_config_file: None,
            extra_files: Vec::new(),
        },
        ConformanceCase {
            name: "run --token --dry-run never redeems or decrypts the token".into(),
            command: vec![
                "run".into(),
                "--token".into(),
                "not-a-real-jwe".into(),
                "--dry-run".into(),
            ],
            stdin: None,
            needs_config: true,
            expected_exit_code: 0,
            expected_stdout: OutputMatcher::Contains("VAULTKEEPER_SECRET".into()),
            expected_stderr: OutputMatcher::Any,
            expected_config_file: None,
            extra_files: Vec::new(),
        },
        ConformanceCase {
            name: "exec emits a deprecation notice on stderr even when the token is invalid".into(),
            command: vec![
                "exec".into(),
                "--token".into(),
                "not-a-real-jwe".into(),
                "--".into(),
                "true".into(),
            ],
            stdin: None,
            needs_config: true,
            expected_exit_code: 1,
            expected_stdout: OutputMatcher::Exact(String::new()),
            expected_stderr: OutputMatcher::Contains("deprecated".into()),
            expected_config_file: None,
            extra_files: Vec::new(),
        },
    ]
}

// ─── Revoke-key cases ────────────────────────────────────────────

fn revoke_key_cases() -> Vec<ConformanceCase> {
    vec![ConformanceCase {
        name: "revoke-key succeeds with valid config".into(),
        command: vec!["revoke-key".into()],
        stdin: None,
        needs_config: true,
        expected_exit_code: 0,
        expected_stdout: OutputMatcher::Contains("revoked successfully".into()),
        expected_stderr: OutputMatcher::Any,
        expected_config_file: None,
        extra_files: Vec::new(),
    }]
}

/// Return all built-in conformance test cases.
pub fn all_cases() -> Vec<ConformanceCase> {
    let mut cases = Vec::new();
    cases.extend(help_cases());
    cases.extend(error_cases());
    cases.extend(argument_validation_cases());
    cases.extend(store_delete_cases());
    cases.extend(config_cases());
    cases.extend(doctor_cases());
    cases.extend(rotate_key_cases());
    cases.extend(revoke_key_cases());
    cases.extend(approve_cases());
    cases.extend(dev_mode_cases());
    cases.extend(backend_capabilities_cases());
    cases.extend(run_cases());
    cases
}

/// Serialize all conformance cases to JSON for the JS runner.
pub fn cases_as_json() -> String {
    serde_json::to_string_pretty(&all_cases()).expect("conformance cases must serialize")
}

/// Check whether an output matches the expected pattern.
pub fn matches_output(matcher: &OutputMatcher, output: &str) -> bool {
    match matcher {
        OutputMatcher::Any => true,
        OutputMatcher::Exact(expected) => output.trim() == expected.trim(),
        OutputMatcher::Contains(substring) => output.contains(substring.as_str()),
        OutputMatcher::Regex(pattern) => regex::Regex::new(pattern)
            .map(|re| re.is_match(output))
            .unwrap_or(false),
        OutputMatcher::JsonContains(expected) => {
            let Ok(parsed) = serde_json::from_str::<serde_json::Value>(output) else {
                return false;
            };
            json_contains(&parsed, expected)
        }
    }
}

/// Check if `haystack` contains all keys/values from `needle`.
fn json_contains(haystack: &serde_json::Value, needle: &serde_json::Value) -> bool {
    match (haystack, needle) {
        (serde_json::Value::Object(h), serde_json::Value::Object(n)) => n
            .iter()
            .all(|(k, v)| h.get(k).is_some_and(|hv| json_contains(hv, v))),
        (serde_json::Value::Array(h), serde_json::Value::Array(n)) => {
            n.iter().all(|nv| h.iter().any(|hv| json_contains(hv, nv)))
        }
        _ => haystack == needle,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cases_serialize_to_json() {
        let json = cases_as_json();
        let parsed: Vec<ConformanceCase> =
            serde_json::from_str(&json).expect("round-trip must succeed");
        assert_eq!(parsed.len(), all_cases().len());
    }

    #[test]
    fn all_cases_have_names() {
        for case in all_cases() {
            assert!(!case.name.is_empty(), "every case must have a name");
        }
    }

    #[test]
    fn all_cases_have_unique_names() {
        let cases = all_cases();
        let mut names: Vec<&str> = cases.iter().map(|c| c.name.as_str()).collect();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), cases.len(), "duplicate case names found");
    }

    #[test]
    fn matches_output_contains() {
        assert!(matches_output(
            &OutputMatcher::Contains("hello".into()),
            "say hello world"
        ));
        assert!(!matches_output(
            &OutputMatcher::Contains("goodbye".into()),
            "say hello world"
        ));
    }

    #[test]
    fn matches_output_exact() {
        assert!(matches_output(
            &OutputMatcher::Exact("hello".into()),
            "hello"
        ));
        assert!(!matches_output(
            &OutputMatcher::Exact("hello".into()),
            "hello world"
        ));
    }

    #[test]
    fn matches_output_any() {
        assert!(matches_output(&OutputMatcher::Any, "anything"));
        assert!(matches_output(&OutputMatcher::Any, ""));
    }

    #[test]
    fn matches_output_json_contains() {
        let matcher = OutputMatcher::JsonContains(serde_json::json!({"version": 1}));
        assert!(matches_output(&matcher, r#"{"version": 1, "extra": true}"#));
        assert!(!matches_output(&matcher, r#"{"version": 2}"#));
        assert!(!matches_output(&matcher, "not json"));
    }

    #[test]
    fn json_contains_nested() {
        let haystack = serde_json::json!({"a": {"b": 1, "c": 2}, "d": 3});
        let needle = serde_json::json!({"a": {"b": 1}});
        assert!(json_contains(&haystack, &needle));
    }
}
