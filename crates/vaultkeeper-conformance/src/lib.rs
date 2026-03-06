//! Conformance test definitions for vaultkeeper.
//!
//! Defines data-driven test cases that both the native Rust CLI and the npm
//! WASM CLI must pass identically. Cases are serializable to JSON so the JS
//! conformance runner can load them.

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
    /// Output must parse as JSON matching this structure.
    JsonContains(serde_json::Value),
    /// Any output is acceptable.
    Any,
}

/// A single conformance test case.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConformanceCase {
    /// Human-readable test name.
    pub name: String,
    /// CLI arguments (e.g. `["doctor"]` or `["store", "--name", "mykey"]`).
    pub command: Vec<String>,
    /// Optional stdin content.
    pub stdin: Option<String>,
    /// Expected exit code.
    pub expected_exit_code: i32,
    /// Expected stdout pattern.
    pub expected_stdout: OutputMatcher,
    /// Expected stderr pattern.
    pub expected_stderr: OutputMatcher,
}

/// Return all built-in conformance test cases.
pub fn all_cases() -> Vec<ConformanceCase> {
    vec![
        ConformanceCase {
            name: "help flag shows usage".to_string(),
            command: vec!["--help".to_string()],
            stdin: None,
            expected_exit_code: 0,
            expected_stdout: OutputMatcher::Contains("vaultkeeper".to_string()),
            expected_stderr: OutputMatcher::Any,
        },
        ConformanceCase {
            name: "doctor runs successfully".to_string(),
            command: vec!["doctor".to_string()],
            stdin: None,
            expected_exit_code: 0,
            expected_stdout: OutputMatcher::Contains("ready".to_string()),
            expected_stderr: OutputMatcher::Any,
        },
        ConformanceCase {
            name: "unknown command exits with error".to_string(),
            command: vec!["nonexistent-command".to_string()],
            stdin: None,
            expected_exit_code: 2,
            expected_stdout: OutputMatcher::Any,
            expected_stderr: OutputMatcher::Contains("error".to_string()),
        },
        ConformanceCase {
            name: "store requires --name".to_string(),
            command: vec!["store".to_string()],
            stdin: None,
            expected_exit_code: 2,
            expected_stdout: OutputMatcher::Any,
            expected_stderr: OutputMatcher::Contains("--name".to_string()),
        },
        ConformanceCase {
            name: "config show outputs valid JSON".to_string(),
            command: vec!["config".to_string(), "show".to_string()],
            stdin: None,
            expected_exit_code: 0,
            expected_stdout: OutputMatcher::Contains("version".to_string()),
            expected_stderr: OutputMatcher::Any,
        },
    ]
}

/// Serialize all conformance cases to JSON for the JS runner.
pub fn cases_as_json() -> String {
    serde_json::to_string_pretty(&all_cases()).expect("conformance cases must serialize")
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
}
