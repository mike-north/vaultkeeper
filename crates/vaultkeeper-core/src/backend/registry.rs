//! Backend registry — maps type identifiers to factory functions.

use super::types::SecretBackend;
use crate::errors::VaultError;
use crate::types::BackendConfig;
use std::collections::HashMap;
use std::sync::Mutex;

/// Factory function for creating a [`SecretBackend`] instance.
pub type BackendFactory = Box<dyn Fn(Option<&BackendConfig>) -> Box<dyn SecretBackend> + Send + Sync>;

/// Registry of backend factories, keyed by type identifier.
pub struct BackendRegistry {
    factories: Mutex<HashMap<String, BackendFactory>>,
}

impl BackendRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            factories: Mutex::new(HashMap::new()),
        }
    }

    /// Register a backend factory for the given type identifier.
    pub fn register<F>(&self, backend_type: &str, factory: F)
    where
        F: Fn(Option<&BackendConfig>) -> Box<dyn SecretBackend> + Send + Sync + 'static,
    {
        let mut factories = self.factories.lock().expect("registry lock poisoned");
        factories.insert(backend_type.to_string(), Box::new(factory));
    }

    /// Create a backend instance by type identifier.
    pub fn create(
        &self,
        backend_type: &str,
        config: Option<&BackendConfig>,
    ) -> Result<Box<dyn SecretBackend>, VaultError> {
        let factories = self.factories.lock().expect("registry lock poisoned");
        let factory = factories.get(backend_type).ok_or_else(|| {
            VaultError::BackendUnavailable {
                message: format!("Unknown backend type: {backend_type}"),
                reason: "unknown-type".to_string(),
                attempted: vec![backend_type.to_string()],
            }
        })?;
        Ok(factory(config))
    }

    /// Check whether a backend type is registered.
    pub fn has(&self, backend_type: &str) -> bool {
        let factories = self.factories.lock().expect("registry lock poisoned");
        factories.contains_key(backend_type)
    }
}

impl Default for BackendRegistry {
    fn default() -> Self {
        Self::new()
    }
}
