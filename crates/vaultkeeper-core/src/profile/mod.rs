//! The environment profile primitive (issue #277).
//!
//! A profile is a named, declarative binding set: env-var name → secret
//! source → materialization mode → policy. Profiles live at
//! `$CONFIG_DIR/profiles/<name>.json` (or a `--profile-file <path>`
//! override) — never inside `config.json`, which is machine-global vault
//! machinery with a different lifecycle. A profile contains no secrets, only
//! names and policy, so it is safe to commit.
//!
//! All schema, validation, and output rendering live here in core; only
//! argument parsing is per-host (see `vaultkeeper-cli`'s `profile`
//! subcommand).

pub mod lint;
pub mod loader;
pub mod render;
pub mod types;

use crate::errors::VaultError;

pub use lint::{LintBaseline, LintResult, LoosenWarning, UnattendedRestartWarning, lint_profile};
pub use loader::{
    EntrySource, LoadedProfile, ProfileDefaults, ProfileEntry, SIGNING_LEASE_DEFAULT_TTL_SECONDS,
    SIGNING_LEASE_MAX_TTL_SECONDS, load_profile_from_str,
};
pub use render::{render_lint, render_list, render_show, scaffold_profile};
pub use types::{
    Materialize, MaterializeMode, MinTrust, ProfileEntries, ProfileEntryRaw, ProfileFile,
};

/// Filename suffix for a profile file within the profiles directory.
pub const PROFILE_FILE_EXTENSION: &str = ".json";

/// Directory name (relative to `$CONFIG_DIR`) that holds named profiles.
pub const PROFILES_DIR_NAME: &str = "profiles";

/// Hard cap on a profile name's length, in bytes.
const MAX_PROFILE_NAME_LEN: usize = 128;

/// Validate a profile name before it is ever used to construct a filesystem
/// path (issue #277's `profile_path`/`profile init|show|lint <NAME>`
/// surface).
///
/// Without this check a hostile name such as `../evil` or `a/b` lets
/// `profile_path` join outside `$CONFIG_DIR/profiles/` entirely — an
/// arbitrary-file-write via `write_file`'s parent-directory auto-creation on
/// `init`, and an arbitrary-file-read on `show`/`lint`. The allowlist below
/// is intentionally conservative: `[A-Za-z0-9][A-Za-z0-9._-]*`, no path
/// separators, no `..` sequence anywhere in the name (not just at the
/// start), non-empty, and capped at [`MAX_PROFILE_NAME_LEN`] bytes.
///
/// # Errors
/// Returns [`VaultError::ConfigValidation`] naming the specific violation.
pub fn validate_profile_name(name: &str) -> Result<(), VaultError> {
    fn invalid(name: &str, reason: &str) -> VaultError {
        VaultError::ConfigValidation {
            message: format!("Invalid profile name \"{name}\": {reason}"),
            field: "name".to_string(),
            config_file_path: None,
        }
    }

    if name.is_empty() {
        return Err(invalid(name, "must not be empty"));
    }
    if name.len() > MAX_PROFILE_NAME_LEN {
        return Err(invalid(
            name,
            &format!("must be at most {MAX_PROFILE_NAME_LEN} bytes"),
        ));
    }
    if name.contains("..") {
        return Err(invalid(name, "must not contain \"..\""));
    }
    if name.contains('/') || name.contains('\\') {
        return Err(invalid(name, "must not contain a path separator"));
    }

    let mut chars = name.chars();
    // Unwrap is safe: the emptiness check above guarantees a first char.
    let first = chars.next().unwrap();
    if !first.is_ascii_alphanumeric() {
        return Err(invalid(
            name,
            "must start with an ASCII letter or digit (not '-', '.', or whitespace)",
        ));
    }
    if !chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')) {
        return Err(invalid(
            name,
            "must match [A-Za-z0-9][A-Za-z0-9._-]* (no whitespace or other punctuation)",
        ));
    }

    Ok(())
}

/// Compute the path a named profile would live at, under `config_dir`.
///
/// # Errors
/// Returns [`VaultError::ConfigValidation`] if `name` fails
/// [`validate_profile_name`] — checked *before* any path construction, so a
/// hostile name never reaches the filesystem.
pub fn profile_path(
    config_dir: &std::path::Path,
    name: &str,
) -> Result<std::path::PathBuf, VaultError> {
    validate_profile_name(name)?;
    Ok(config_dir
        .join(PROFILES_DIR_NAME)
        .join(format!("{name}{PROFILE_FILE_EXTENSION}")))
}

#[cfg(test)]
mod profile_name_validation_tests {
    use super::*;

    #[test]
    fn accepts_ordinary_names() {
        assert!(validate_profile_name("github-mcp").is_ok());
        assert!(validate_profile_name("my_profile.v2").is_ok());
        assert!(validate_profile_name("A1").is_ok());
    }

    #[test]
    fn rejects_parent_directory_traversal() {
        assert!(validate_profile_name("../evil").is_err());
        assert!(validate_profile_name("..").is_err());
        assert!(validate_profile_name("a/../../etc/passwd").is_err());
        assert!(validate_profile_name("foo..bar").is_err());
    }

    #[test]
    fn rejects_path_separators() {
        assert!(validate_profile_name("a/b").is_err());
        assert!(validate_profile_name("a\\b").is_err());
    }

    #[test]
    fn rejects_absolute_paths() {
        assert!(validate_profile_name("/etc/passwd").is_err());
    }

    #[test]
    fn rejects_empty_name() {
        assert!(validate_profile_name("").is_err());
    }

    #[test]
    fn rejects_dot_only_name() {
        assert!(validate_profile_name(".").is_err());
    }

    #[test]
    fn rejects_leading_dash() {
        assert!(validate_profile_name("-rf").is_err());
    }

    #[test]
    fn rejects_leading_dot() {
        assert!(validate_profile_name(".hidden").is_err());
    }

    #[test]
    fn rejects_leading_whitespace() {
        assert!(validate_profile_name(" leading").is_err());
    }

    #[test]
    fn rejects_embedded_whitespace() {
        assert!(validate_profile_name("has space").is_err());
    }

    #[test]
    fn rejects_overlong_name() {
        let overlong = "a".repeat(MAX_PROFILE_NAME_LEN + 1);
        assert!(validate_profile_name(&overlong).is_err());
    }

    #[test]
    fn accepts_name_at_the_length_cap() {
        let exactly_max = "a".repeat(MAX_PROFILE_NAME_LEN);
        assert!(validate_profile_name(&exactly_max).is_ok());
    }

    #[test]
    fn profile_path_rejects_a_hostile_name_before_constructing_any_path() {
        let err =
            profile_path(std::path::Path::new("/config"), "../evil").expect_err("must reject");
        assert!(matches!(err, VaultError::ConfigValidation { .. }));
    }

    #[test]
    fn profile_path_accepts_a_valid_name() {
        let path = profile_path(std::path::Path::new("/config"), "github-mcp").unwrap();
        assert_eq!(
            path,
            std::path::Path::new("/config/profiles/github-mcp.json")
        );
    }
}

#[cfg(test)]
mod schema_round_trip_tests {
    use super::types::ProfileFile;

    /// Strip `//`-prefixed JSONC line comments, for test-only use on the
    /// issue's illustrative example. Only strips a comment when `//` starts
    /// a line (after leading whitespace) — sufficient for this fixture,
    /// which never puts `//` inside a string value.
    fn strip_jsonc_line_comments(input: &str) -> String {
        input
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    const SCHEMA_EXAMPLE_JSONC: &str = r#"{
      "version": 1,
      "name": "github-mcp",
      "entries": {
        "GITHUB_TOKEN": {
          // Rung 2 — unmodified third-party server reads a real token.
          "secret": "github-pat",
          "materialize": "secret",
          "minTrust": "registry",
          "requirePresencePerUse": false
        },
        "VK_DB_CREDENTIAL": {
          // Rung 3 — vaultkeeper-aware consumer; env carries a secret-access lease.
          "secret": "prod-db-password",
          "materialize": "lease",
          "minTrust": "sigstore",
          "ttlSeconds": 900,
          "useLimit": 5
        },
        "VK_SIGNING_LEASE": {
          // Rung 3 — session signing lease. NOT unattended-restart-safe.
          "signingKey": "release-signer",
          "materialize": "lease",
          "ttlSeconds": 28800,
          "useLimit": 200,
          "requirePresenceAtMint": true
        }
      }
    }"#;

    /// AC3: the issue's `## Schema` example round-trips through serde
    /// unchanged. JSON object/array structural equality (not textual/byte
    /// equality — key order is not semantically meaningful for a JSON
    /// object) is checked via `serde_json::Value`, which vaultkeeper's
    /// `serde_json` dependency (no `preserve_order` feature) already
    /// normalizes into a sorted map.
    #[test]
    fn schema_example_round_trips_through_serde_unchanged() {
        let stripped = strip_jsonc_line_comments(SCHEMA_EXAMPLE_JSONC);
        let original: serde_json::Value = serde_json::from_str(&stripped).unwrap();

        let parsed: ProfileFile = serde_json::from_str(&stripped).unwrap();
        let round_tripped = serde_json::to_value(&parsed).unwrap();

        assert_eq!(original, round_tripped);
    }
}
