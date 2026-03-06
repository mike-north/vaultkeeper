//! In-memory secret backend for testing.
//!
//! Stores secrets in a `HashMap` with no external dependencies.
//! Suitable for unit, integration, and e2e tests.

use crate::errors::VaultError;
use super::types::{ListableBackend, SecretBackend};
use std::collections::HashMap;
use std::sync::Mutex;

/// A fully in-memory `SecretBackend` for testing.
///
/// This backend stores secrets in a plain `HashMap` and has no external
/// dependencies. It implements both [`SecretBackend`] and [`ListableBackend`].
pub struct InMemoryBackend {
    store: Mutex<HashMap<String, String>>,
}

impl InMemoryBackend {
    /// Create a new empty in-memory backend.
    pub fn new() -> Self {
        Self {
            store: Mutex::new(HashMap::new()),
        }
    }

    /// Remove all stored secrets. Useful for test teardown.
    pub fn clear(&self) {
        self.store.lock().expect("store lock poisoned").clear();
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

#[async_trait::async_trait]
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
        self.store
            .lock()
            .expect("store lock poisoned")
            .remove(id);
        Ok(())
    }

    async fn exists(&self, id: &str) -> Result<bool, VaultError> {
        Ok(self
            .store
            .lock()
            .expect("store lock poisoned")
            .contains_key(id))
    }
}

#[async_trait::async_trait]
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

#[cfg(test)]
mod tests {
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

    #[tokio::test]
    async fn delete_nonexistent_is_noop() {
        let backend = InMemoryBackend::new();
        // Should not error
        backend.delete("nonexistent").await.unwrap();
    }
}
