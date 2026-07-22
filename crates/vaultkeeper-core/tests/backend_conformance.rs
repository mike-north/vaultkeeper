//! Backend-level conformance runner for the core Rust `InMemoryBackend`
//! (issue #312, AC4).
//!
//! Runs the exact same [`vaultkeeper_conformance::backend_cases`] corpus the
//! TS `InMemoryBackend` double runs in
//! `packages/test-helpers/test/conformance/backend-cases.test.ts`, each case
//! against a freshly constructed `vaultkeeper_core::backend::InMemoryBackend`
//! — proving cross-language parity: the same data-driven scenarios pass
//! against both languages' `InMemoryBackend`.
//!
//! @see crates/vaultkeeper-conformance/src/backend_cases.rs — case definitions
//! @see packages/test-helpers/test/conformance/backend-cases.test.ts — JS-side runner

use vaultkeeper_conformance::backend_cases::{
    BackendConformanceCase, BackendStep, all_backend_cases,
};
use vaultkeeper_core::InMemoryBackend;
use vaultkeeper_core::backend::{
    ListableBackend, PresenceCapableBackend, SecretBackend, SigningBackend,
};
use vaultkeeper_core::errors::VaultError;
use vaultkeeper_core::signing::ed25519::{parse_public_key_pem, verify};
use vaultkeeper_core::types::SigningAlgorithm;

/// Run a single [`BackendConformanceCase`] against a fresh `InMemoryBackend`,
/// returning `Err` with a description of the first failing step rather than
/// panicking, so the caller can aggregate every case's result.
async fn run_case(case: &BackendConformanceCase) -> Result<(), String> {
    let backend = InMemoryBackend::new();

    for step in &case.steps {
        match step {
            BackendStep::Store { id, secret } => backend
                .store(id, secret)
                .await
                .map_err(|e| format!("store({id:?}) failed: {e}"))?,
            BackendStep::ExpectRetrieve { id, secret } => {
                let got = backend
                    .retrieve(id)
                    .await
                    .map_err(|e| format!("retrieve({id:?}) failed: {e}"))?;
                if &got != secret {
                    return Err(format!(
                        "retrieve({id:?}) returned {got:?}, expected {secret:?}"
                    ));
                }
            }
            BackendStep::ExpectRetrieveNotFound { id } => {
                let err = backend.retrieve(id).await;
                match err {
                    Err(VaultError::SecretNotFound { .. }) => {}
                    Err(e) => {
                        return Err(format!("retrieve({id:?}) expected SecretNotFound, got {e}"));
                    }
                    Ok(v) => {
                        return Err(format!(
                            "retrieve({id:?}) expected SecretNotFound, got Ok({v:?})"
                        ));
                    }
                }
            }
            BackendStep::Delete { id } => backend
                .delete(id)
                .await
                .map_err(|e| format!("delete({id:?}) failed: {e}"))?,
            BackendStep::ExpectDeleteNotFound { id } => match backend.delete(id).await {
                Err(VaultError::SecretNotFound { .. }) => {}
                Err(e) => return Err(format!("delete({id:?}) expected SecretNotFound, got {e}")),
                Ok(()) => {
                    return Err(format!(
                        "delete({id:?}) expected SecretNotFound, got Ok(())"
                    ));
                }
            },
            BackendStep::ExpectExists { id, exists } => {
                let got = backend
                    .exists(id)
                    .await
                    .map_err(|e| format!("exists({id:?}) failed: {e}"))?;
                if got != *exists {
                    return Err(format!("exists({id:?}) returned {got}, expected {exists}"));
                }
            }
            BackendStep::ExpectListContains { ids } => {
                let listed = backend
                    .list()
                    .await
                    .map_err(|e| format!("list() failed: {e}"))?;
                for id in ids {
                    if !listed.contains(id) {
                        return Err(format!("list() {listed:?} does not contain {id:?}"));
                    }
                }
            }
            BackendStep::GenerateSigningKey { id } => backend
                .generate_signing_key(id, SigningAlgorithm::EdDsa)
                .await
                .map_err(|e| format!("generate_signing_key({id:?}) failed: {e}"))?,
            BackendStep::ExpectGenerateSigningKeyAlreadyExists { id } => {
                match backend
                    .generate_signing_key(id, SigningAlgorithm::EdDsa)
                    .await
                {
                    Err(VaultError::SigningKeyAlreadyExists { .. }) => {}
                    Err(e) => {
                        return Err(format!(
                            "generate_signing_key({id:?}) expected SigningKeyAlreadyExists, got {e}"
                        ));
                    }
                    Ok(()) => {
                        return Err(format!(
                            "generate_signing_key({id:?}) expected SigningKeyAlreadyExists, got Ok(())"
                        ));
                    }
                }
            }
            BackendStep::ExpectSignRoundTrips { id, message } => {
                let public_key = backend
                    .get_public_key(id)
                    .await
                    .map_err(|e| format!("get_public_key({id:?}) failed: {e}"))?;
                let signature = backend
                    .sign_with_key(id, message.as_bytes())
                    .await
                    .map_err(|e| format!("sign_with_key({id:?}) failed: {e}"))?;
                let verifying_key = parse_public_key_pem(&public_key.public_key_pem)
                    .map_err(|e| format!("parse_public_key_pem({id:?}) failed: {e}"))?;
                if !verify(&verifying_key, message.as_bytes(), &signature) {
                    return Err(format!(
                        "sign_with_key({id:?}) signature did not verify against its own public key"
                    ));
                }
                if verify(&verifying_key, b"a tampered payload", &signature) {
                    return Err(format!(
                        "sign_with_key({id:?}) signature verified against a tampered payload"
                    ));
                }
            }
            BackendStep::ExpectGetPublicKeyNotFound { id } => {
                match backend.get_public_key(id).await {
                    Err(VaultError::SigningKeyNotFound { .. }) => {}
                    Err(e) => {
                        return Err(format!(
                            "get_public_key({id:?}) expected SigningKeyNotFound, got {e}"
                        ));
                    }
                    Ok(k) => {
                        return Err(format!(
                            "get_public_key({id:?}) expected SigningKeyNotFound, got Ok({k:?})"
                        ));
                    }
                }
            }
            BackendStep::ExpectSignNotFound { id } => {
                match backend.sign_with_key(id, b"data").await {
                    Err(VaultError::SigningKeyNotFound { .. }) => {}
                    Err(e) => {
                        return Err(format!(
                            "sign_with_key({id:?}) expected SigningKeyNotFound, got {e}"
                        ));
                    }
                    Ok(_) => {
                        return Err(format!(
                            "sign_with_key({id:?}) expected SigningKeyNotFound, got Ok(_)"
                        ));
                    }
                }
            }
            BackendStep::ExpectPresencePerUse { value } => {
                let caps = backend
                    .get_capabilities()
                    .await
                    .map_err(|e| format!("get_capabilities() failed: {e}"))?;
                if caps.presence_per_use != *value {
                    return Err(format!(
                        "get_capabilities().presence_per_use was {}, expected {value}",
                        caps.presence_per_use
                    ));
                }
            }
        }
    }

    Ok(())
}

#[tokio::test]
async fn all_backend_conformance_cases_pass_against_core_in_memory_backend() {
    let cases = all_backend_cases();
    assert!(
        !cases.is_empty(),
        "the backend conformance corpus must not be empty"
    );

    let mut failures = Vec::new();
    for case in &cases {
        if let Err(msg) = run_case(case).await {
            failures.push(format!("Case '{}' failed: {msg}", case.name));
        }
    }

    if !failures.is_empty() {
        panic!(
            "{} of {} backend conformance cases failed:\n\n{}",
            failures.len(),
            cases.len(),
            failures.join("\n\n")
        );
    }
}
