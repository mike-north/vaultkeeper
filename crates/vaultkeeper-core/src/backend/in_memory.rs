//! In-memory secret backend for testing.
//!
//! Stores secrets in a `HashMap` with no external dependencies.
//! Suitable for unit, integration, and e2e tests.
//!
//! Also implements [`SigningBackend`] and [`PresenceCapableBackend`] (issue
//! #312), mirroring the TypeScript `@vaultkeeper/test-helpers`
//! `InMemoryBackend` double exactly: real in-memory Ed25519 keys (the private
//! key never leaves this backend) and an honest `presence_per_use: false`
//! capability report (no touch device, no biometric prompt — see
//! [`PresenceCapableBackend`]'s docs on host-attested self-reporting). Unlike
//! [`super::FileBackend`]'s [`super::signing_store`], signing keys here are
//! held purely in memory (no `HostPlatform`, no disk persistence) since this
//! backend has no host to persist through.

use super::types::{
    BackendCapabilities, ListableBackend, PresenceCapableBackend, SecretBackend, SigningBackend,
};
use crate::errors::VaultError;
use crate::signing::ed25519::{kid_for_verifying_key, sign as ed25519_sign};
use crate::types::{SigningAlgorithm, SigningPublicKey};
use ed25519_dalek::SigningKey;
use ed25519_dalek::pkcs8::EncodePublicKey;
use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use std::collections::HashMap;
use std::sync::Mutex;
use zeroize::Zeroize;

/// A fully in-memory `SecretBackend` for testing.
///
/// This backend stores secrets in a plain `HashMap` and has no external
/// dependencies. It implements [`SecretBackend`], [`ListableBackend`],
/// [`SigningBackend`], and [`PresenceCapableBackend`].
pub struct InMemoryBackend {
    store: Mutex<HashMap<String, String>>,
    signing_keys: Mutex<HashMap<String, SigningKey>>,
}

impl InMemoryBackend {
    /// Create a new empty in-memory backend.
    pub fn new() -> Self {
        Self {
            store: Mutex::new(HashMap::new()),
            signing_keys: Mutex::new(HashMap::new()),
        }
    }

    /// Remove all stored secrets and signing keys. Useful for test teardown.
    pub fn clear(&self) {
        self.store.lock().expect("store lock poisoned").clear();
        self.signing_keys
            .lock()
            .expect("signing key store lock poisoned")
            .clear();
    }

    /// The number of secrets currently stored.
    pub fn size(&self) -> usize {
        self.store.lock().expect("store lock poisoned").len()
    }
}

impl Default for InMemoryBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl SecretBackend for InMemoryBackend {
    fn backend_type(&self) -> &str {
        "memory"
    }

    fn display_name(&self) -> &str {
        "In-Memory Backend"
    }

    async fn is_available(&self) -> bool {
        true
    }

    async fn store(&self, id: &str, secret: &str) -> Result<(), VaultError> {
        self.store
            .lock()
            .expect("store lock poisoned")
            .insert(id.to_string(), secret.to_string());
        Ok(())
    }

    async fn retrieve(&self, id: &str) -> Result<String, VaultError> {
        self.store
            .lock()
            .expect("store lock poisoned")
            .get(id)
            .cloned()
            .ok_or_else(|| VaultError::SecretNotFound {
                message: format!("Secret not found: {id}"),
            })
    }

    async fn delete(&self, id: &str) -> Result<(), VaultError> {
        // Contract fidelity (issue #312): `SecretBackend::delete` returns
        // `SecretNotFound` for a missing id — matching `FileBackend::delete`
        // and the TS `InMemoryBackend` double's `delete()` — rather than a
        // lenient no-op that no real backend exhibits.
        let mut store = self.store.lock().expect("store lock poisoned");
        if store.remove(id).is_none() {
            return Err(VaultError::SecretNotFound {
                message: format!("Secret not found: {id}"),
            });
        }
        Ok(())
    }

    async fn exists(&self, id: &str) -> Result<bool, VaultError> {
        Ok(self
            .store
            .lock()
            .expect("store lock poisoned")
            .contains_key(id))
    }

    fn as_presence_capable(&self) -> Option<&dyn PresenceCapableBackend> {
        Some(self)
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl ListableBackend for InMemoryBackend {
    async fn list(&self) -> Result<Vec<String>, VaultError> {
        Ok(self
            .store
            .lock()
            .expect("store lock poisoned")
            .keys()
            .cloned()
            .collect())
    }
}

/// `InMemoryBackend` has no physical presence mechanism (no touch device, no
/// biometric prompt) — it always reports `presence_per_use: false`, in the
/// same [`BackendCapabilities`] vocabulary every other backend uses, so a
/// `--require-presence-per-use` request against this double is correctly
/// refused with `NotCapable` rather than silently satisfied. Mirrors the
/// TypeScript double's `getCapabilities` exactly.
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl PresenceCapableBackend for InMemoryBackend {
    async fn get_capabilities(&self) -> Result<BackendCapabilities, VaultError> {
        Ok(BackendCapabilities {
            presence_per_use: false,
            presence_enforced_operations: None,
        })
    }
}

/// Signing keys are generated, held, and used entirely in memory — the
/// private key never leaves this backend and is never persisted to disk.
/// Mirrors the TypeScript double's `SigningBackend` implementation (real
/// Ed25519 keys via `node:crypto`) using `ed25519-dalek` on the Rust side.
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl SigningBackend for InMemoryBackend {
    async fn generate_signing_key(
        &self,
        id: &str,
        algorithm: SigningAlgorithm,
    ) -> Result<(), VaultError> {
        // `SigningAlgorithm` currently has exactly one variant (`EdDsa`); this
        // match is exhaustive today and, like `signing_store`, will fail to
        // compile if a second algorithm is ever added until this backend
        // explicitly decides whether it supports it.
        match algorithm {
            SigningAlgorithm::EdDsa => {}
        }

        let mut signing_keys = self
            .signing_keys
            .lock()
            .expect("signing key store lock poisoned");
        if signing_keys.contains_key(id) {
            return Err(VaultError::SigningKeyAlreadyExists {
                message: format!("Signing key already exists: {id}"),
                id: id.to_string(),
            });
        }

        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed)
            .map_err(|e| VaultError::Other(format!("Failed to generate signing key: {e}")))?;
        let signing_key = SigningKey::from_bytes(&seed);
        seed.zeroize();
        signing_keys.insert(id.to_string(), signing_key);
        Ok(())
    }

    async fn get_public_key(&self, id: &str) -> Result<SigningPublicKey, VaultError> {
        let signing_keys = self
            .signing_keys
            .lock()
            .expect("signing key store lock poisoned");
        let signing_key = signing_keys
            .get(id)
            .ok_or_else(|| VaultError::SigningKeyNotFound {
                message: format!("Signing key not found: {id}"),
                id: id.to_string(),
            })?;
        let verifying_key = signing_key.verifying_key();

        let public_key_pem = verifying_key
            .to_public_key_pem(LineEnding::LF)
            .map_err(|e| VaultError::Other(format!("Failed to encode signing public key: {e}")))?;
        let kid = kid_for_verifying_key(&verifying_key);

        Ok(SigningPublicKey {
            public_key_pem,
            algorithm: SigningAlgorithm::EdDsa,
            kid,
        })
    }

    async fn sign_with_key(&self, id: &str, data: &[u8]) -> Result<Vec<u8>, VaultError> {
        let signing_keys = self
            .signing_keys
            .lock()
            .expect("signing key store lock poisoned");
        let signing_key = signing_keys
            .get(id)
            .ok_or_else(|| VaultError::SigningKeyNotFound {
                message: format!("Signing key not found: {id}"),
                id: id.to_string(),
            })?;
        Ok(ed25519_sign(signing_key, data))
    }
}

#[cfg(test)]
mod tests {
    use super::super::types::{get_backend_capabilities, is_presence_capable_backend};
    use super::*;

    #[tokio::test]
    async fn store_and_retrieve() {
        let backend = InMemoryBackend::new();
        backend.store("key1", "secret1").await.unwrap();
        let val = backend.retrieve("key1").await.unwrap();
        assert_eq!(val, "secret1");
    }

    #[tokio::test]
    async fn retrieve_nonexistent_returns_error() {
        let backend = InMemoryBackend::new();
        let result = backend.retrieve("missing").await;
        assert!(matches!(result, Err(VaultError::SecretNotFound { .. })));
    }

    #[tokio::test]
    async fn delete_removes_secret() {
        let backend = InMemoryBackend::new();
        backend.store("key1", "secret1").await.unwrap();
        assert!(backend.exists("key1").await.unwrap());

        backend.delete("key1").await.unwrap();
        assert!(!backend.exists("key1").await.unwrap());
    }

    #[tokio::test]
    async fn exists_returns_false_for_missing() {
        let backend = InMemoryBackend::new();
        assert!(!backend.exists("nope").await.unwrap());
    }

    #[tokio::test]
    async fn list_returns_all_keys() {
        let backend = InMemoryBackend::new();
        backend.store("a", "1").await.unwrap();
        backend.store("b", "2").await.unwrap();
        backend.store("c", "3").await.unwrap();

        let mut keys = backend.list().await.unwrap();
        keys.sort();
        assert_eq!(keys, vec!["a", "b", "c"]);
    }

    #[tokio::test]
    async fn clear_removes_everything() {
        let backend = InMemoryBackend::new();
        backend.store("x", "y").await.unwrap();
        assert_eq!(backend.size(), 1);

        backend.clear();
        assert_eq!(backend.size(), 0);
        assert!(!backend.exists("x").await.unwrap());
    }

    #[tokio::test]
    async fn is_always_available() {
        let backend = InMemoryBackend::new();
        assert!(backend.is_available().await);
    }

    #[tokio::test]
    async fn overwrite_existing_secret() {
        let backend = InMemoryBackend::new();
        backend.store("key", "v1").await.unwrap();
        backend.store("key", "v2").await.unwrap();
        assert_eq!(backend.retrieve("key").await.unwrap(), "v2");
        assert_eq!(backend.size(), 1);
    }

    #[test]
    fn backend_type_and_display_name() {
        let backend = InMemoryBackend::new();
        assert_eq!(backend.backend_type(), "memory");
        assert_eq!(backend.display_name(), "In-Memory Backend");
    }

    // Regression test for issue #312: `delete` on a missing id previously
    // silently succeeded (a no-op), diverging from `FileBackend::delete` and
    // the TS `InMemoryBackend` double, both of which return
    // `SecretNotFound`. This would fail against the pre-fix behavior (which
    // returned `Ok(())` unconditionally).
    #[tokio::test]
    async fn delete_nonexistent_returns_secret_not_found() {
        let backend = InMemoryBackend::new();
        let err = backend.delete("nonexistent").await.unwrap_err();
        assert!(matches!(err, VaultError::SecretNotFound { .. }));
    }

    // -----------------------------------------------------------------
    // Issue #312 AC3 — the core `in_memory` backend implements
    // `SigningBackend`: it generates a keypair, signs, and the signature
    // verifies against the public key — matching the TS double's behavior.
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn sign_with_key_produces_a_signature_verifiable_against_the_public_key() {
        let backend = InMemoryBackend::new();
        backend
            .generate_signing_key("my-key", SigningAlgorithm::EdDsa)
            .await
            .unwrap();

        let public_key = backend.get_public_key("my-key").await.unwrap();
        let message = b"vaultkeeper issue #312";
        let signature = backend.sign_with_key("my-key", message).await.unwrap();

        let verifying_key =
            crate::signing::ed25519::parse_public_key_pem(&public_key.public_key_pem).unwrap();
        assert!(crate::signing::ed25519::verify(
            &verifying_key,
            message,
            &signature
        ));
        assert_eq!(public_key.algorithm, SigningAlgorithm::EdDsa);
    }

    #[tokio::test]
    async fn sign_with_key_absent_id_returns_typed_error_not_panic() {
        let backend = InMemoryBackend::new();
        let err = backend
            .sign_with_key("no-such-key", b"data")
            .await
            .unwrap_err();
        assert!(matches!(err, VaultError::SigningKeyNotFound { id, .. } if id == "no-such-key"));
    }

    #[tokio::test]
    async fn get_public_key_absent_id_returns_typed_error() {
        let backend = InMemoryBackend::new();
        let err = backend.get_public_key("ghost").await.unwrap_err();
        assert!(matches!(err, VaultError::SigningKeyNotFound { .. }));
    }

    #[tokio::test]
    async fn generate_signing_key_rejects_duplicate_id() {
        let backend = InMemoryBackend::new();
        backend
            .generate_signing_key("dup", SigningAlgorithm::EdDsa)
            .await
            .unwrap();
        let err = backend
            .generate_signing_key("dup", SigningAlgorithm::EdDsa)
            .await
            .unwrap_err();
        assert!(matches!(err, VaultError::SigningKeyAlreadyExists { id, .. } if id == "dup"));
    }

    #[tokio::test]
    async fn tampered_signature_fails_verification() {
        let backend = InMemoryBackend::new();
        backend
            .generate_signing_key("tamper-me", SigningAlgorithm::EdDsa)
            .await
            .unwrap();
        let public_key = backend.get_public_key("tamper-me").await.unwrap();
        let mut signature = backend
            .sign_with_key("tamper-me", b"original message")
            .await
            .unwrap();
        signature[0] ^= 0xff;

        let verifying_key =
            crate::signing::ed25519::parse_public_key_pem(&public_key.public_key_pem).unwrap();
        assert!(!crate::signing::ed25519::verify(
            &verifying_key,
            b"original message",
            &signature
        ));
    }

    #[tokio::test]
    async fn clear_removes_signing_keys_too() {
        let backend = InMemoryBackend::new();
        backend
            .generate_signing_key("goes-away", SigningAlgorithm::EdDsa)
            .await
            .unwrap();
        backend.clear();
        let err = backend.get_public_key("goes-away").await.unwrap_err();
        assert!(matches!(err, VaultError::SigningKeyNotFound { .. }));
    }

    #[tokio::test]
    async fn signing_key_and_secret_with_the_same_name_coexist_without_collision() {
        let backend = InMemoryBackend::new();
        backend
            .store("shared-name", "the-secret-value")
            .await
            .unwrap();
        backend
            .generate_signing_key("shared-name", SigningAlgorithm::EdDsa)
            .await
            .unwrap();

        let secret = backend.retrieve("shared-name").await.unwrap();
        assert_eq!(secret, "the-secret-value");

        let signature = backend.sign_with_key("shared-name", b"msg").await.unwrap();
        let public_key = backend.get_public_key("shared-name").await.unwrap();
        let verifying_key =
            crate::signing::ed25519::parse_public_key_pem(&public_key.public_key_pem).unwrap();
        assert!(crate::signing::ed25519::verify(
            &verifying_key,
            b"msg",
            &signature
        ));

        backend.delete("shared-name").await.unwrap();
        assert!(!backend.exists("shared-name").await.unwrap());

        let signature_after_delete = backend.sign_with_key("shared-name", b"msg").await.unwrap();
        assert!(crate::signing::ed25519::verify(
            &verifying_key,
            b"msg",
            &signature_after_delete
        ));
    }

    // -----------------------------------------------------------------
    // Presence capability: `InMemoryBackend` never claims physical presence.
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn reports_no_presence_capability() {
        let backend = InMemoryBackend::new();
        let caps = get_backend_capabilities(&backend).await.unwrap();
        assert!(!caps.presence_per_use);
        assert_eq!(caps.presence_enforced_operations, None);
    }

    #[test]
    fn as_presence_capable_returns_self() {
        let backend = InMemoryBackend::new();
        assert!(is_presence_capable_backend(&backend));
    }
}
