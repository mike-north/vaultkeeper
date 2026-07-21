//! Integration test for the environment profile loader (issue #277 AC7).
//!
//! Exercises the full host-backed path: a real `HostPlatform` implementation
//! serves `config.json` and a profile file from disk-shaped storage, the
//! loader's config-conversion helper (`ProfileDefaults::from_vault_defaults`)
//! turns the loaded `config.json` defaults into profile defaults, and
//! `load_profile_from_str` validates the profile against them — the same
//! sequence `vaultkeeper-cli`'s `profile show`/`lint` commands run. The
//! matching WASM-bridge half of this proof is
//! `packages/vaultkeeper-wasm/src/test/profile.test.ts`, which drives the
//! same loader through the compiled WASM binary.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use vaultkeeper_core::backend::{ExecOptions, ExecOutput, HostPlatform, Platform};
use vaultkeeper_core::errors::VaultError;
use vaultkeeper_core::profile::{EntrySource, ProfileDefaults, load_profile_from_str};

struct TestHost {
    files: Mutex<HashMap<PathBuf, Vec<u8>>>,
    config_dir: PathBuf,
}

impl TestHost {
    fn new(config_json: &str) -> Self {
        let config_dir = PathBuf::from("/test/config");
        let mut files = HashMap::new();
        files.insert(
            config_dir.join("config.json"),
            config_json.as_bytes().to_vec(),
        );
        Self {
            files: Mutex::new(files),
            config_dir,
        }
    }

    fn add_file(&self, path: PathBuf, content: &str) {
        self.files.lock().unwrap().insert(path, content.into());
    }
}

#[async_trait::async_trait]
impl HostPlatform for TestHost {
    async fn exec(
        &self,
        _cmd: &str,
        _args: &[&str],
        _options: ExecOptions<'_>,
    ) -> Result<ExecOutput, VaultError> {
        unimplemented!("not exercised by this test")
    }
    async fn read_file(&self, path: &Path) -> Result<Vec<u8>, VaultError> {
        self.files
            .lock()
            .unwrap()
            .get(path)
            .cloned()
            .ok_or_else(|| VaultError::Other(format!("not found: {}", path.display())))
    }
    async fn write_file(
        &self,
        _path: &Path,
        _content: &[u8],
        _mode: u32,
    ) -> Result<(), VaultError> {
        unimplemented!("not exercised by this test")
    }
    async fn file_exists(&self, path: &Path) -> Result<bool, VaultError> {
        Ok(self.files.lock().unwrap().contains_key(path))
    }
    async fn delete_file(&self, _path: &Path) -> Result<(), VaultError> {
        unimplemented!("not exercised by this test")
    }
    async fn list_dir(&self, _path: &Path) -> Result<Vec<String>, VaultError> {
        unimplemented!("not exercised by this test")
    }
    fn platform(&self) -> Platform {
        Platform::Linux
    }
    fn config_dir(&self) -> &Path {
        &self.config_dir
    }
}

const PROFILE_JSON: &str = r#"{
    "version": 1,
    "name": "github-mcp",
    "entries": {
        "GITHUB_TOKEN": {
            "secret": "github-pat",
            "materialize": "secret",
            "minTrust": "registry"
        },
        "VK_DB_CREDENTIAL": {
            "secret": "prod-db-password",
            "materialize": "lease"
        }
    }
}"#;

/// AC7 (Rust half): the profile loader is reachable end-to-end from a real
/// `HostPlatform` — `config.json` is read through the host, its
/// `defaults.ttlMinutes` is converted to seconds by
/// `ProfileDefaults::from_vault_defaults`, and the profile file (also read
/// through the host) is validated against those resolved defaults.
#[tokio::test]
async fn loader_is_reachable_through_a_real_host_platform() {
    let host = TestHost::new(
        &serde_json::to_string(&serde_json::json!({
            "version": 1,
            "backends": [{ "type": "file", "enabled": true }],
            "keyRotation": { "gracePeriodDays": 7 },
            "defaults": { "ttlMinutes": 10, "trustTier": 2 }
        }))
        .unwrap(),
    );
    let profile_path = host.config_dir().join("profiles").join("github-mcp.json");
    host.add_file(profile_path.clone(), PROFILE_JSON);

    let cfg = vaultkeeper_core::config::load_config(&host).await.unwrap();
    let defaults = ProfileDefaults::from_vault_defaults(&cfg.defaults);
    // The host's config.json set ttlMinutes: 10 — the loader must convert
    // that to seconds (AC4) before it ever reaches the profile loader.
    assert_eq!(defaults.ttl_seconds, 600);

    let content = host.read_file(&profile_path).await.unwrap();
    let json = String::from_utf8(content).unwrap();
    let loaded = load_profile_from_str(&json, &defaults).unwrap();

    assert_eq!(loaded.name, "github-mcp");
    assert_eq!(loaded.entries.len(), 2);
    let (_, db_credential) = loaded
        .entries
        .iter()
        .find(|(name, _)| name == "VK_DB_CREDENTIAL")
        .unwrap();
    // materialize: "lease" with no explicit ttlSeconds picks up the
    // host-config-derived default, proving the whole chain (host → config →
    // ProfileDefaults → loader) is wired together, not just the loader in
    // isolation.
    assert_eq!(db_credential.ttl_seconds, Some(600));
    assert_eq!(
        db_credential.source,
        EntrySource::Secret("prod-db-password".to_string())
    );
}
