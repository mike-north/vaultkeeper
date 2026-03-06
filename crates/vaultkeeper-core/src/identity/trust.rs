//! Trust verification — classify executables into trust tiers.
//!
//! Tier 1 — Sigstore: cryptographic provenance (not yet implemented for arbitrary binaries).
//! Tier 2 — Registry: hash found in the approved trust manifest.
//! Tier 3 — Unverified: default fallback / TOFU first-encounter.
//!
//! TOFU (Trust On First Use): on the first encounter the hash is recorded.
//! If the hash changes on a subsequent call a `tofu_conflict` is signalled.

use crate::backend::HostPlatform;
use crate::errors::VaultError;
use crate::types::TrustTier;
use super::hash::hash_executable;
use super::manifest::{add_trusted_hash, is_trusted, load_manifest, save_manifest};
use super::types::{IdentityInfo, TrustOptions, TrustVerificationResult};
use std::path::Path;

/// Verify the trust tier of the executable at `exec_path`.
///
/// Pass `"dev"` as `exec_path` to enable dev-mode bypass (skips all hash
/// verification and returns Tier 3 immediately).
pub async fn verify_trust(
    host: &dyn HostPlatform,
    exec_path: &str,
    options: Option<&TrustOptions>,
) -> Result<TrustVerificationResult, VaultError> {
    // Dev-mode bypass
    if exec_path == "dev" {
        return Ok(TrustVerificationResult {
            identity: IdentityInfo {
                hash: "dev".to_string(),
                trust_tier: TrustTier::Dev,
                verified: false,
            },
            tofu_conflict: false,
            reason: "Dev mode — hash verification skipped".to_string(),
        });
    }

    let namespace = options
        .and_then(|o| o.namespace.as_deref())
        .unwrap_or(exec_path);

    // Compute the current hash of the executable.
    let current_hash = hash_executable(host, Path::new(exec_path)).await?;

    // Load the manifest for TOFU and registry checks.
    let manifest = load_manifest(host).await?;

    // --- Tier 1: Sigstore (placeholder — always falls through) ---
    let skip_sigstore = options.and_then(|o| o.skip_sigstore).unwrap_or(false);
    if !skip_sigstore {
        let sigstore_verified = try_sigstore(exec_path).await;
        if sigstore_verified {
            let updated = add_trusted_hash(&manifest, namespace, &current_hash);
            save_manifest(host, &updated).await?;
            return Ok(TrustVerificationResult {
                identity: IdentityInfo {
                    hash: current_hash,
                    trust_tier: TrustTier::Sigstore,
                    verified: true,
                },
                tofu_conflict: false,
                reason: "Sigstore bundle verified".to_string(),
            });
        }
    }

    // --- Tier 2: Registry (manifest) ---
    if is_trusted(&manifest, namespace, &current_hash) {
        return Ok(TrustVerificationResult {
            identity: IdentityInfo {
                hash: current_hash,
                trust_tier: TrustTier::Tofu,
                verified: true,
            },
            tofu_conflict: false,
            reason: "Hash found in trust manifest".to_string(),
        });
    }

    // --- TOFU check ---
    if let Some(existing) = manifest.get(namespace)
        && !existing.hashes.is_empty()
    {
        // The namespace is known but the current hash is not approved.
        return Ok(TrustVerificationResult {
            identity: IdentityInfo {
                hash: current_hash,
                trust_tier: TrustTier::Dev,
                verified: false,
            },
            tofu_conflict: true,
            reason: "Hash changed from a previously approved value — re-approval required"
                .to_string(),
        });
    }

    // --- Tier 3: First encounter — record via TOFU ---
    let updated = add_trusted_hash(&manifest, namespace, &current_hash);
    save_manifest(host, &updated).await?;
    Ok(TrustVerificationResult {
        identity: IdentityInfo {
            hash: current_hash,
            trust_tier: TrustTier::Dev,
            verified: false,
        },
        tofu_conflict: false,
        reason: "First encounter — hash recorded via TOFU".to_string(),
    })
}

/// Attempt Sigstore bundle verification (Tier 1).
///
/// Currently always returns `false` — full Sigstore bundle verification
/// is not yet available for arbitrary binaries.
async fn try_sigstore(_exec_path: &str) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{ExecOutput, Platform};
    use async_trait::async_trait;
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    /// A mock HostPlatform that stores files in memory.
    struct MockHost {
        files: Mutex<HashMap<PathBuf, Vec<u8>>>,
        config_dir: PathBuf,
    }

    impl MockHost {
        fn new() -> Self {
            Self {
                files: Mutex::new(HashMap::new()),
                config_dir: PathBuf::from("/mock/config"),
            }
        }

        fn add_file(&self, path: &str, content: &[u8]) {
            self.files
                .lock()
                .unwrap()
                .insert(PathBuf::from(path), content.to_vec());
        }
    }

    #[async_trait]
    impl HostPlatform for MockHost {
        async fn exec(
            &self,
            _cmd: &str,
            _args: &[&str],
            _stdin: Option<&[u8]>,
        ) -> Result<ExecOutput, VaultError> {
            Ok(ExecOutput {
                stdout: Vec::new(),
                stderr: Vec::new(),
                exit_code: 0,
            })
        }

        async fn read_file(&self, path: &Path) -> Result<Vec<u8>, VaultError> {
            self.files
                .lock()
                .unwrap()
                .get(path)
                .cloned()
                .ok_or_else(|| VaultError::Other(format!("File not found: {}", path.display())))
        }

        async fn write_file(
            &self,
            path: &Path,
            content: &[u8],
            _mode: u32,
        ) -> Result<(), VaultError> {
            self.files
                .lock()
                .unwrap()
                .insert(path.to_path_buf(), content.to_vec());
            Ok(())
        }

        async fn file_exists(&self, path: &Path) -> Result<bool, VaultError> {
            Ok(self.files.lock().unwrap().contains_key(path))
        }

        async fn delete_file(&self, path: &Path) -> Result<(), VaultError> {
            self.files
                .lock()
                .unwrap()
                .remove(path)
                .ok_or_else(|| VaultError::Other(format!("Not found: {}", path.display())))?;
            Ok(())
        }

        async fn list_dir(&self, path: &Path) -> Result<Vec<String>, VaultError> {
            let files = self.files.lock().unwrap();
            Ok(files
                .keys()
                .filter_map(|k| {
                    if k.parent() == Some(path) {
                        k.file_name().and_then(|n| n.to_str()).map(String::from)
                    } else {
                        None
                    }
                })
                .collect())
        }

        fn platform(&self) -> Platform {
            Platform::Linux
        }

        fn config_dir(&self) -> &Path {
            &self.config_dir
        }
    }

    #[tokio::test]
    async fn dev_mode_bypass() {
        let host = MockHost::new();
        let result = verify_trust(&host, "dev", None).await.unwrap();
        assert_eq!(result.identity.hash, "dev");
        assert_eq!(result.identity.trust_tier, TrustTier::Dev);
        assert!(!result.identity.verified);
        assert!(!result.tofu_conflict);
    }

    #[tokio::test]
    async fn first_encounter_records_tofu() {
        let host = MockHost::new();
        host.add_file("/usr/bin/test-app", b"binary-content");

        let result = verify_trust(&host, "/usr/bin/test-app", None).await.unwrap();
        assert_eq!(result.identity.trust_tier, TrustTier::Dev);
        assert!(!result.identity.verified);
        assert!(!result.tofu_conflict);
        assert!(result.reason.contains("First encounter"));

        // Manifest should have been saved
        let manifest = load_manifest(&host).await.unwrap();
        assert!(is_trusted(&manifest, "/usr/bin/test-app", &result.identity.hash));
    }

    #[tokio::test]
    async fn subsequent_encounter_returns_tier2() {
        let host = MockHost::new();
        host.add_file("/usr/bin/test-app", b"binary-content");

        // First encounter records TOFU
        let first = verify_trust(&host, "/usr/bin/test-app", None).await.unwrap();
        assert!(!first.tofu_conflict);

        // Second encounter with same binary should find it in manifest
        let second = verify_trust(&host, "/usr/bin/test-app", None).await.unwrap();
        assert_eq!(second.identity.trust_tier, TrustTier::Tofu);
        assert!(second.identity.verified);
        assert!(!second.tofu_conflict);
        assert!(second.reason.contains("trust manifest"));
    }

    #[tokio::test]
    async fn hash_change_triggers_tofu_conflict() {
        let host = MockHost::new();
        host.add_file("/usr/bin/test-app", b"original-binary");

        // First encounter
        verify_trust(&host, "/usr/bin/test-app", None).await.unwrap();

        // Change the binary
        host.add_file("/usr/bin/test-app", b"modified-binary");

        // Should detect the TOFU conflict
        let result = verify_trust(&host, "/usr/bin/test-app", None).await.unwrap();
        assert!(result.tofu_conflict);
        assert_eq!(result.identity.trust_tier, TrustTier::Dev);
        assert!(!result.identity.verified);
        assert!(result.reason.contains("re-approval"));
    }

    #[tokio::test]
    async fn custom_namespace() {
        let host = MockHost::new();
        host.add_file("/usr/bin/test-app", b"binary-content");

        let opts = TrustOptions {
            namespace: Some("custom-ns".to_string()),
            ..Default::default()
        };

        let result = verify_trust(&host, "/usr/bin/test-app", Some(&opts))
            .await
            .unwrap();
        assert!(!result.tofu_conflict);

        // Should be stored under custom namespace
        let manifest = load_manifest(&host).await.unwrap();
        assert!(is_trusted(&manifest, "custom-ns", &result.identity.hash));
        assert!(!is_trusted(
            &manifest,
            "/usr/bin/test-app",
            &result.identity.hash
        ));
    }
}
