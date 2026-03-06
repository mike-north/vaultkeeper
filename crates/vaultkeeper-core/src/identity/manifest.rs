//! Trust manifest management — load, save, and query approved executable hashes.

use super::types::{TrustManifest, TrustManifestEntry};
use crate::backend::HostPlatform;
use crate::errors::VaultError;
use crate::types::TrustTier;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

const MANIFEST_FILENAME: &str = "trust-manifest.json";

/// On-disk representation of the trust manifest.
#[derive(Debug, Serialize, Deserialize)]
struct RawManifest {
    version: u32,
    entries: HashMap<String, RawEntry>,
}

/// On-disk representation of a single manifest entry.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawEntry {
    hashes: Vec<String>,
    trust_tier: u8,
}

/// Load the trust manifest from the config directory.
/// Returns an empty manifest if the file does not exist.
pub async fn load_manifest(host: &dyn HostPlatform) -> Result<TrustManifest, VaultError> {
    let manifest_path = host.config_dir().join(MANIFEST_FILENAME);

    match host.file_exists(&manifest_path).await {
        Ok(true) => {}
        _ => return Ok(HashMap::new()),
    }

    let content = host.read_file(&manifest_path).await?;
    let json = String::from_utf8(content)
        .map_err(|e| VaultError::Other(format!("Invalid UTF-8 in trust manifest: {e}")))?;

    let raw: RawManifest = serde_json::from_str(&json)
        .map_err(|e| VaultError::Other(format!("Failed to parse trust manifest: {e}")))?;

    let mut manifest = HashMap::new();
    for (namespace, entry) in raw.entries {
        let tier = match entry.trust_tier {
            1 => TrustTier::Sigstore,
            2 => TrustTier::Tofu,
            _ => TrustTier::Dev,
        };
        manifest.insert(
            namespace,
            TrustManifestEntry {
                hashes: entry.hashes,
                trust_tier: tier,
            },
        );
    }

    Ok(manifest)
}

/// Save the trust manifest to the config directory.
pub async fn save_manifest(
    host: &dyn HostPlatform,
    manifest: &TrustManifest,
) -> Result<(), VaultError> {
    let mut entries = HashMap::new();
    for (namespace, entry) in manifest {
        entries.insert(
            namespace.clone(),
            RawEntry {
                hashes: entry.hashes.clone(),
                trust_tier: entry.trust_tier as u8,
            },
        );
    }

    let raw = RawManifest {
        version: 1,
        entries,
    };

    let json = serde_json::to_string_pretty(&raw)
        .map_err(|e| VaultError::Other(format!("Failed to serialize trust manifest: {e}")))?;

    let manifest_path = host.config_dir().join(MANIFEST_FILENAME);
    host.write_file(&manifest_path, json.as_bytes(), 0o600)
        .await
}

/// Return a new manifest with `hash` added under `namespace`.
/// If the namespace does not exist, it is created with tier 3 (Dev/Unverified).
/// The trust tier of an existing entry is not changed.
pub fn add_trusted_hash(manifest: &TrustManifest, namespace: &str, hash: &str) -> TrustManifest {
    let mut next = manifest.clone();
    let entry = next
        .entry(namespace.to_string())
        .or_insert_with(|| TrustManifestEntry {
            hashes: Vec::new(),
            trust_tier: TrustTier::Dev,
        });
    if !entry.hashes.iter().any(|h| h == hash) {
        entry.hashes.push(hash.to_string());
    }
    next
}

/// Return `true` if `hash` is in the approved list for `namespace`.
pub fn is_trusted(manifest: &TrustManifest, namespace: &str, hash: &str) -> bool {
    manifest
        .get(namespace)
        .is_some_and(|entry| entry.hashes.iter().any(|h| h == hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_manifest() -> TrustManifest {
        HashMap::new()
    }

    #[test]
    fn is_trusted_returns_false_for_empty_manifest() {
        assert!(!is_trusted(&empty_manifest(), "app", "abc123"));
    }

    #[test]
    fn add_trusted_hash_creates_new_namespace() {
        let m = add_trusted_hash(&empty_manifest(), "app", "hash1");
        assert!(is_trusted(&m, "app", "hash1"));
        assert!(!is_trusted(&m, "app", "hash2"));
    }

    #[test]
    fn add_trusted_hash_appends_to_existing() {
        let m = add_trusted_hash(&empty_manifest(), "app", "hash1");
        let m = add_trusted_hash(&m, "app", "hash2");
        assert!(is_trusted(&m, "app", "hash1"));
        assert!(is_trusted(&m, "app", "hash2"));
    }

    #[test]
    fn add_trusted_hash_deduplicates() {
        let m = add_trusted_hash(&empty_manifest(), "app", "hash1");
        let m = add_trusted_hash(&m, "app", "hash1");
        assert_eq!(m["app"].hashes.len(), 1);
    }

    #[test]
    fn add_trusted_hash_preserves_existing_tier() {
        let mut m = empty_manifest();
        m.insert(
            "app".to_string(),
            TrustManifestEntry {
                hashes: vec!["old".to_string()],
                trust_tier: TrustTier::Tofu,
            },
        );
        let m = add_trusted_hash(&m, "app", "new");
        assert_eq!(m["app"].trust_tier, TrustTier::Tofu);
    }

    #[test]
    fn new_namespace_gets_dev_tier() {
        let m = add_trusted_hash(&empty_manifest(), "new-app", "abc");
        assert_eq!(m["new-app"].trust_tier, TrustTier::Dev);
    }
}
