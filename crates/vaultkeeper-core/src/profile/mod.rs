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

pub use lint::{LintBaseline, LintResult, LoosenWarning, UnattendedRestartWarning, lint_profile};
pub use loader::{
    EntrySource, LoadedProfile, ProfileDefaults, ProfileEntry, load_profile_from_str,
};
pub use render::{render_lint, render_list, render_show, scaffold_profile};
pub use types::{
    Materialize, MaterializeMode, MinTrust, ProfileEntries, ProfileEntryRaw, ProfileFile,
};

/// Filename suffix for a profile file within the profiles directory.
pub const PROFILE_FILE_EXTENSION: &str = ".json";

/// Directory name (relative to `$CONFIG_DIR`) that holds named profiles.
pub const PROFILES_DIR_NAME: &str = "profiles";

/// Compute the path a named profile would live at, under `config_dir`.
#[must_use]
pub fn profile_path(config_dir: &std::path::Path, name: &str) -> std::path::PathBuf {
    config_dir
        .join(PROFILES_DIR_NAME)
        .join(format!("{name}{PROFILE_FILE_EXTENSION}"))
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
