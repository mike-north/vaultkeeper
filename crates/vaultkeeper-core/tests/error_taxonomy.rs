//! Error-taxonomy parity test (issue #236).
//!
//! `ALL_ERROR_CODES` is the single source of truth for every code that can
//! cross the WASM boundary. This test proves the Rust half of the contract:
//! every `VaultError` variant produces exactly one of those codes, every code
//! in the table is produced by some variant, and the structured context
//! fields (`vault_error_fields`) carry the values a caller actually
//! constructed the error with — not fabricated or dropped data.
//!
//! The TypeScript half of the same contract is
//! `packages/vaultkeeper-wasm/src/test/error-parity.test.ts`, which fetches
//! `ALL_ERROR_CODES` from the compiled WASM binary (via the exported
//! `allVaultErrorCodes()`) and asserts its own reconstruction map handles
//! exactly this set, then round-trips real `vault_error_to_js`-produced
//! values (via the exported `__testAllVaultErrors()`) through `mapWasmError`.

use std::collections::BTreeSet;

use serde_json::json;
use vaultkeeper_core::{
    ALL_ERROR_CODES, all_variants_for_parity_test, vault_error_code, vault_error_fields,
};

/// Every `VaultError` variant must map to a code that is in `ALL_ERROR_CODES`,
/// and every code in `ALL_ERROR_CODES` must be produced by some variant.
/// `all_variants_for_parity_test()` is defined to hold exactly one instance
/// per variant, so a passing set-equality check here also proves there are no
/// duplicate codes and no variant was left out of the fixture list.
#[test]
fn every_variant_maps_to_a_table_code_and_vice_versa() {
    let variants = all_variants_for_parity_test();
    let produced_codes: BTreeSet<&'static str> = variants.iter().map(vault_error_code).collect();
    let table_codes: BTreeSet<&'static str> = ALL_ERROR_CODES.iter().copied().collect();

    assert_eq!(
        produced_codes, table_codes,
        "vault_error_code()'s output and ALL_ERROR_CODES have drifted apart \
         (see crates/vaultkeeper-core/src/errors.rs)"
    );

    // No duplicate codes: exactly one variant per table entry.
    assert_eq!(
        variants.len(),
        ALL_ERROR_CODES.len(),
        "all_variants_for_parity_test() must hold exactly one variant per ALL_ERROR_CODES entry"
    );
}

/// `ALL_ERROR_CODES` itself must not contain duplicates — a duplicate would
/// let the equality check above pass even if two variants shared a code.
#[test]
fn all_error_codes_table_has_no_duplicates() {
    let unique: BTreeSet<&'static str> = ALL_ERROR_CODES.iter().copied().collect();
    assert_eq!(
        unique.len(),
        ALL_ERROR_CODES.len(),
        "ALL_ERROR_CODES contains a duplicate code"
    );
}

/// Spot-checks that `vault_error_fields()` carries through the exact values
/// each variant was constructed with, for every variant that has context
/// fields beyond `message`. Variants with no extra fields (e.g.
/// `SecretNotFound`, `KeyRotated`) are proven field-less by the exhaustive
/// match in `vault_error_fields` itself (its `_ => {}` arm), so they are not
/// repeated here.
#[test]
fn vault_error_fields_round_trips_context_values() {
    use vaultkeeper_core::{ExecutableTrustRequiredReason, VaultError};

    let cases: Vec<(VaultError, serde_json::Value)> = vec![
        (
            VaultError::Decryption {
                message: "m".into(),
                path: "/a.enc".into(),
            },
            json!({ "path": "/a.enc" }),
        ),
        (
            VaultError::TokenExpired {
                message: "m".into(),
                can_refresh: true,
            },
            json!({ "canRefresh": true }),
        ),
        (
            VaultError::BackendLocked {
                message: "m".into(),
                interactive: true,
            },
            json!({ "interactive": true }),
        ),
        (
            VaultError::DeviceNotPresent {
                message: "m".into(),
                timeout_ms: 5000,
            },
            json!({ "timeoutMs": 5000 }),
        ),
        (
            VaultError::BackendUnavailable {
                message: "m".into(),
                reason: "all-failed".into(),
                attempted: vec!["a".into(), "b".into()],
            },
            json!({ "reason": "all-failed", "attempted": ["a", "b"] }),
        ),
        (
            VaultError::PluginNotFound {
                message: "m".into(),
                plugin: "p".into(),
                install_url: "https://x".into(),
            },
            json!({ "plugin": "p", "installUrl": "https://x" }),
        ),
        (
            VaultError::IdentityMismatch {
                message: "m".into(),
                previous_hash: "aaaa".into(),
                current_hash: "bbbb".into(),
            },
            json!({ "previousHash": "aaaa", "currentHash": "bbbb" }),
        ),
        (
            VaultError::ExecutableTrustRequired {
                message: "m".into(),
                reason: ExecutableTrustRequiredReason::ConflictingChoice,
            },
            json!({ "reason": "conflicting-choice" }),
        ),
        (
            VaultError::InvalidAlgorithm {
                message: "m".into(),
                algorithm: "RS256".into(),
                allowed: vec!["EdDSA".into()],
            },
            json!({ "algorithm": "RS256", "allowed": ["EdDSA"] }),
        ),
        (
            VaultError::Setup {
                message: "m".into(),
                dependency: "openssl".into(),
            },
            json!({ "dependency": "openssl" }),
        ),
        (
            VaultError::Filesystem {
                message: "m".into(),
                path: "/x".into(),
                permission: "read".into(),
                code: Some("EACCES".into()),
            },
            json!({ "path": "/x", "permission": "read", "code": "EACCES" }),
        ),
        (
            VaultError::Filesystem {
                message: "m".into(),
                path: "/x".into(),
                permission: "read".into(),
                code: None,
            },
            json!({ "path": "/x", "permission": "read" }),
        ),
        (
            VaultError::NotCapable {
                message: "m".into(),
                backend_type: "keychain".into(),
                capability: "presencePerUse".into(),
            },
            json!({ "backendType": "keychain", "capability": "presencePerUse" }),
        ),
        (
            VaultError::PresenceDeclined {
                message: "m".into(),
                backend_type: "yubikey".into(),
            },
            json!({ "backendType": "yubikey" }),
        ),
        (
            VaultError::PresenceTimeout {
                message: "m".into(),
                backend_type: "yubikey".into(),
                timeout_ms: 15000,
            },
            json!({ "backendType": "yubikey", "timeoutMs": 15000 }),
        ),
        (
            VaultError::SigningKeyNotFound {
                message: "m".into(),
                id: "release-key".into(),
            },
            json!({ "keyName": "release-key" }),
        ),
        (
            VaultError::SigningKeyAlreadyExists {
                message: "m".into(),
                id: "release-key".into(),
            },
            json!({ "keyName": "release-key" }),
        ),
        (
            VaultError::SigningNotSupported {
                message: "m".into(),
                backend_type: "keychain".into(),
                built_in_signing_backends: vec!["file".into()],
            },
            json!({ "backendType": "keychain", "builtInSigningBackends": ["file"] }),
        ),
        (
            VaultError::Exec {
                message: "m".into(),
                command: "curl".into(),
            },
            json!({ "command": "curl" }),
        ),
        (
            VaultError::Fetch {
                message: "m".into(),
                url: "https://x/{{secret}}".into(),
            },
            json!({ "url": "https://x/{{secret}}" }),
        ),
        (
            VaultError::ConfigValidation {
                message: "m".into(),
                field: "backends[0].path".into(),
                config_file_path: Some("/config.json".into()),
            },
            json!({ "field": "backends[0].path", "configFilePath": "/config.json" }),
        ),
        (
            VaultError::ConfigValidation {
                message: "m".into(),
                field: "backends[0].path".into(),
                config_file_path: None,
            },
            json!({ "field": "backends[0].path" }),
        ),
        (
            VaultError::UnknownBackendType {
                message: "m".into(),
                field: "backends[0].type".into(),
                backend_type: "made-up".into(),
                known_backend_types: vec!["file".into(), "keychain".into()],
                config_file_path: Some("/config.json".into()),
            },
            json!({
                "field": "backends[0].type",
                "backendType": "made-up",
                "knownTypes": ["file", "keychain"],
                "configFilePath": "/config.json",
            }),
        ),
        (
            VaultError::ConfigParse {
                message: "m".into(),
                path: "/config.json".into(),
                line: Some(3),
                column: Some(12),
            },
            json!({ "path": "/config.json", "line": 3, "column": 12 }),
        ),
        (
            VaultError::ConfigParse {
                message: "m".into(),
                path: "/config.json".into(),
                line: None,
                column: None,
            },
            json!({ "path": "/config.json" }),
        ),
    ];

    for (err, expected) in cases {
        let fields = vault_error_fields(&err);
        let actual = serde_json::Value::Object(fields);
        assert_eq!(
            actual,
            expected,
            "vault_error_fields() mismatch for {}",
            vault_error_code(&err)
        );
    }
}

/// Variants with no context fields beyond `message` must produce an empty
/// field map — proving `vault_error_fields`'s catch-all arm doesn't leak
/// stray data for them.
#[test]
fn field_less_variants_produce_no_extra_fields() {
    use vaultkeeper_core::VaultError;

    let field_less = vec![
        VaultError::SecretNotFound {
            message: "m".into(),
        },
        VaultError::KeyRotated {
            message: "m".into(),
        },
        VaultError::KeyRevoked {
            message: "m".into(),
        },
        VaultError::TokenRevoked {
            message: "m".into(),
        },
        VaultError::UsageLimitExceeded {
            message: "m".into(),
        },
        VaultError::RotationInProgress {
            message: "m".into(),
        },
        VaultError::AuthorizationDenied {
            message: "m".into(),
        },
        VaultError::InvalidKeyMaterial {
            message: "m".into(),
        },
        VaultError::InvalidToken {
            message: "m".into(),
        },
        VaultError::AccessorConsumed {
            message: "m".into(),
        },
        VaultError::Other("m".into()),
    ];

    for err in field_less {
        let fields = vault_error_fields(&err);
        assert!(
            fields.is_empty(),
            "expected no extra fields for {}, got {fields:?}",
            vault_error_code(&err)
        );
    }
}
