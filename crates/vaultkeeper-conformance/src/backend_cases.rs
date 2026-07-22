//! Backend-level conformance cases (issue #312).
//!
//! [`super::ConformanceCase`] (the original corpus) is CLI-argv-only: every
//! case spawns the `vaultkeeper` binary and asserts on stdout/stderr/exit
//! code, always against the hardcoded `file` backend (issues #273, #297).
//! That shape cannot exercise a `SecretBackend` implementation directly —
//! there is no CLI invocation that selects a specific backend instance, and
//! the `@vaultkeeper/test-helpers` `InMemoryBackend` double is a
//! library-level construct with no CLI wiring at all.
//!
//! This module is a second, narrower data-driven corpus, scoped to exactly
//! the store/retrieve/delete/exists/list/sign/capability behavior a backend
//! implementation itself is responsible for — applicable to *any*
//! `SecretBackend` + `SigningBackend` + `PresenceCapableBackend`
//! implementation, not just one wired to a CLI. Both the TS
//! `InMemoryBackend` double (`@vaultkeeper/test-helpers`) and the Rust core
//! `InMemoryBackend` (`vaultkeeper_core::backend::InMemoryBackend`) run the
//! exact same [`BackendConformanceCase`] list, each against a freshly
//! constructed backend instance, proving the double is held to the same
//! contract in both languages and that the two languages agree with each
//! other (issue #312 ACs 1, 2, 4).

use serde::{Deserialize, Serialize};

/// A single step in a [`BackendConformanceCase`]'s scenario, executed in
/// order against one freshly constructed backend instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "camelCase")]
pub enum BackendStep {
    /// `store(id, secret)` must succeed.
    Store { id: String, secret: String },
    /// `retrieve(id)` must succeed and equal `secret`.
    ExpectRetrieve { id: String, secret: String },
    /// `retrieve(id)` must fail with "secret not found".
    ExpectRetrieveNotFound { id: String },
    /// `delete(id)` must succeed.
    Delete { id: String },
    /// `delete(id)` must fail with "secret not found".
    ExpectDeleteNotFound { id: String },
    /// `exists(id)` must equal `exists`.
    ExpectExists { id: String, exists: bool },
    /// `list()` must include every id in `ids`.
    ExpectListContains { ids: Vec<String> },
    /// `list()` must NOT include any id in `ids`.
    ExpectListDoesNotContain { ids: Vec<String> },
    /// `generateSigningKey(id, 'EdDSA')` must succeed.
    GenerateSigningKey { id: String },
    /// `generateSigningKey(id, 'EdDSA')` must fail because `id` already has
    /// a signing key enrolled.
    ExpectGenerateSigningKeyAlreadyExists { id: String },
    /// `signWithKey(id, message)` must succeed and the resulting signature
    /// must verify against `getPublicKey(id)`'s public key, and must NOT
    /// verify against `message` mutated (a tampered check).
    ExpectSignRoundTrips { id: String, message: String },
    /// `getPublicKey(id)` must fail because no signing key exists under
    /// `id`.
    ExpectGetPublicKeyNotFound { id: String },
    /// `signWithKey(id, ...)` must fail because no signing key exists under
    /// `id`.
    ExpectSignNotFound { id: String },
    /// `getCapabilities().presencePerUse` must equal `value`.
    ExpectPresencePerUse { value: bool },
}

/// A single backend-level conformance case: a named scenario, run against a
/// freshly constructed backend instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackendConformanceCase {
    /// Human-readable test name.
    pub name: String,
    /// Steps executed in order against one freshly constructed backend.
    pub steps: Vec<BackendStep>,
}

/// Return all built-in backend-level conformance cases.
///
/// Scoped to what an in-memory backend can support: no case here requires a
/// real OS credential store, hardware device, or external process — see this
/// module's docs for the CLI-argv-only cases that are explicitly out of
/// scope for the double (issue #312).
pub fn all_backend_cases() -> Vec<BackendConformanceCase> {
    vec![
        BackendConformanceCase {
            name: "store then retrieve returns the same secret".into(),
            steps: vec![
                BackendStep::Store {
                    id: "conformance-key".into(),
                    secret: "conformance-secret".into(),
                },
                BackendStep::ExpectRetrieve {
                    id: "conformance-key".into(),
                    secret: "conformance-secret".into(),
                },
            ],
        },
        BackendConformanceCase {
            name: "retrieve of a missing id returns not found".into(),
            steps: vec![BackendStep::ExpectRetrieveNotFound {
                id: "never-stored".into(),
            }],
        },
        BackendConformanceCase {
            name: "delete removes a stored secret".into(),
            steps: vec![
                BackendStep::Store {
                    id: "delete-me".into(),
                    secret: "x".into(),
                },
                BackendStep::Delete {
                    id: "delete-me".into(),
                },
                BackendStep::ExpectRetrieveNotFound {
                    id: "delete-me".into(),
                },
            ],
        },
        BackendConformanceCase {
            name: "delete of a missing id returns not found".into(),
            steps: vec![BackendStep::ExpectDeleteNotFound {
                id: "never-existed".into(),
            }],
        },
        BackendConformanceCase {
            name: "exists reflects store/delete state".into(),
            steps: vec![
                BackendStep::ExpectExists {
                    id: "existence-probe".into(),
                    exists: false,
                },
                BackendStep::Store {
                    id: "existence-probe".into(),
                    secret: "v".into(),
                },
                BackendStep::ExpectExists {
                    id: "existence-probe".into(),
                    exists: true,
                },
                BackendStep::Delete {
                    id: "existence-probe".into(),
                },
                BackendStep::ExpectExists {
                    id: "existence-probe".into(),
                    exists: false,
                },
            ],
        },
        BackendConformanceCase {
            name: "list reflects every stored id".into(),
            steps: vec![
                BackendStep::Store {
                    id: "list-a".into(),
                    secret: "1".into(),
                },
                BackendStep::Store {
                    id: "list-b".into(),
                    secret: "2".into(),
                },
                BackendStep::ExpectListContains {
                    ids: vec!["list-a".into(), "list-b".into()],
                },
            ],
        },
        BackendConformanceCase {
            name: "list omits an id after it is deleted".into(),
            steps: vec![
                BackendStep::Store {
                    id: "list-delete-me".into(),
                    secret: "v".into(),
                },
                BackendStep::ExpectListContains {
                    ids: vec!["list-delete-me".into()],
                },
                BackendStep::Delete {
                    id: "list-delete-me".into(),
                },
                BackendStep::ExpectListDoesNotContain {
                    ids: vec!["list-delete-me".into()],
                },
            ],
        },
        BackendConformanceCase {
            name: "a generated signing key signs and verifies against its own public key".into(),
            steps: vec![
                BackendStep::GenerateSigningKey {
                    id: "sign-key".into(),
                },
                BackendStep::ExpectSignRoundTrips {
                    id: "sign-key".into(),
                    message: "vaultkeeper issue #312 conformance".into(),
                },
            ],
        },
        BackendConformanceCase {
            name: "generate signing key rejects a duplicate id".into(),
            steps: vec![
                BackendStep::GenerateSigningKey { id: "dup".into() },
                BackendStep::ExpectGenerateSigningKeyAlreadyExists { id: "dup".into() },
            ],
        },
        BackendConformanceCase {
            name: "get public key for a missing signing key id returns not found".into(),
            steps: vec![BackendStep::ExpectGetPublicKeyNotFound { id: "ghost".into() }],
        },
        BackendConformanceCase {
            name: "sign with a missing signing key id returns not found".into(),
            steps: vec![BackendStep::ExpectSignNotFound {
                id: "ghost-signer".into(),
            }],
        },
        BackendConformanceCase {
            name: "reports no presence-per-use capability".into(),
            steps: vec![BackendStep::ExpectPresencePerUse { value: false }],
        },
    ]
}

/// Serialize all backend-level conformance cases to JSON for the JS runner.
pub fn backend_cases_as_json() -> String {
    serde_json::to_string_pretty(&all_backend_cases())
        .expect("backend conformance cases must serialize")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cases_serialize_to_json() {
        let json = backend_cases_as_json();
        let parsed: Vec<BackendConformanceCase> =
            serde_json::from_str(&json).expect("round-trip must succeed");
        assert_eq!(parsed.len(), all_backend_cases().len());
    }

    #[test]
    fn all_cases_have_names() {
        for case in all_backend_cases() {
            assert!(!case.name.is_empty(), "every case must have a name");
        }
    }

    #[test]
    fn all_cases_have_unique_names() {
        let cases = all_backend_cases();
        let mut names: Vec<&str> = cases.iter().map(|c| c.name.as_str()).collect();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), cases.len(), "duplicate case names found");
    }

    #[test]
    fn every_case_has_at_least_one_step() {
        for case in all_backend_cases() {
            assert!(!case.steps.is_empty(), "case '{}' has no steps", case.name);
        }
    }
}
