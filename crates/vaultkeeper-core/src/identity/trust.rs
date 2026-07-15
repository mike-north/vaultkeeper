//! Trust verification — classify executables into trust tiers.
//!
//! Tier 1 — Sigstore: cryptographic provenance (not yet implemented for arbitrary binaries).
//! Tier 2 — Registry: hash found in the approved trust manifest.
//! Tier 3 — Unverified: default fallback / TOFU first-encounter.
//!
//! TOFU (Trust On First Use): on the first encounter the hash is recorded.
//! If the hash changes on a subsequent call a `tofu_conflict` is signalled.

use super::hash::hash_executable;
use super::manifest::{add_trusted_hash, is_trusted, load_manifest, save_manifest};
use super::types::{IdentityInfo, TrustManifest, TrustOptions, TrustVerificationResult};
use crate::backend::HostPlatform;
use crate::errors::VaultError;
use crate::types::TrustTier;
use std::path::Path;

/// A trust decision computed by [`verify_trust_pending`] whose persistence
/// side effect (recording the hash in the TOFU manifest) has **not** yet been
/// applied.
///
/// Verification is split from persistence so a caller — notably
/// [`crate::vault::VaultKeeper::setup`] — can validate an executable and mint a
/// token *before* committing the first-encounter manifest write. A failure
/// between verification and [`PendingTrust::commit`] therefore leaves the
/// manifest untouched, avoiding the ordering defect tracked in issue #148 (a
/// TOFU record persisted for an operation that ultimately failed).
#[derive(Debug, Clone)]
pub struct PendingTrust {
    /// The computed identity information.
    pub identity: IdentityInfo,
    /// True when TOFU detected a hash change (re-approval required). No manifest
    /// write is pending in this case.
    pub tofu_conflict: bool,
    /// Human-readable description of how trust was established.
    pub reason: String,
    /// On a [`PendingTrust::tofu_conflict`], the hashes previously approved for
    /// the namespace that the current hash no longer matches (most-recent last).
    /// Empty otherwise.
    pub approved_hashes: Vec<String>,
    /// The manifest to persist on [`PendingTrust::commit`], or `None` when this
    /// decision records nothing (a registry/Sigstore-already-recorded match, the
    /// dev bypass, or a TOFU conflict).
    manifest_to_save: Option<TrustManifest>,
}

impl PendingTrust {
    /// Persist the pending TOFU manifest write, if any. A no-op when there is
    /// nothing to record.
    ///
    /// Call this only after the overall operation has otherwise succeeded (e.g.
    /// the token has been minted) so a failure never leaves a premature TOFU record
    /// behind (issue #148).
    pub async fn commit(&self, host: &dyn HostPlatform) -> Result<(), VaultError> {
        if let Some(manifest) = &self.manifest_to_save {
            save_manifest(host, manifest).await?;
        }
        Ok(())
    }
}

/// Verify the trust tier of the executable at `exec_path` **without** applying
/// any persistence side effect.
///
/// This is the side-effect-free half of trust verification: it computes the
/// hash, consults the manifest (Sigstore → registry match → TOFU), and returns
/// a [`PendingTrust`] describing the decision plus the manifest write (if any)
/// that a subsequent [`PendingTrust::commit`] would apply. No manifest write
/// happens here — see [`PendingTrust`] and issue #148 for why the write is
/// deferred.
///
/// Pass `"dev"` as `exec_path` to enable dev-mode bypass (skips all hash
/// verification and returns Tier 3 immediately, with nothing to commit).
pub async fn verify_trust_pending(
    host: &dyn HostPlatform,
    exec_path: &str,
    options: Option<&TrustOptions>,
) -> Result<PendingTrust, VaultError> {
    // Dev-mode bypass
    if exec_path == "dev" {
        return Ok(PendingTrust {
            identity: IdentityInfo {
                hash: "dev".to_string(),
                trust_tier: TrustTier::Dev,
                verified: false,
            },
            tofu_conflict: false,
            reason: "Dev mode — hash verification skipped".to_string(),
            approved_hashes: Vec::new(),
            manifest_to_save: None,
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
            return Ok(PendingTrust {
                identity: IdentityInfo {
                    hash: current_hash,
                    trust_tier: TrustTier::Sigstore,
                    verified: true,
                },
                tofu_conflict: false,
                reason: "Sigstore bundle verified".to_string(),
                approved_hashes: Vec::new(),
                manifest_to_save: Some(updated),
            });
        }
    }

    // --- Tier 2: Registry (manifest) ---
    if is_trusted(&manifest, namespace, &current_hash) {
        return Ok(PendingTrust {
            identity: IdentityInfo {
                hash: current_hash,
                trust_tier: TrustTier::Tofu,
                verified: true,
            },
            tofu_conflict: false,
            reason: "Hash found in trust manifest".to_string(),
            approved_hashes: Vec::new(),
            manifest_to_save: None,
        });
    }

    // --- TOFU check ---
    if let Some(existing) = manifest.get(namespace)
        && !existing.hashes.is_empty()
    {
        // The namespace is known but the current hash is not approved. Record
        // nothing — the conflicting hash must never be persisted (issue #148).
        return Ok(PendingTrust {
            identity: IdentityInfo {
                hash: current_hash,
                trust_tier: TrustTier::Dev,
                verified: false,
            },
            tofu_conflict: true,
            reason: "Hash changed from a previously approved value — re-approval required"
                .to_string(),
            approved_hashes: existing.hashes.clone(),
            manifest_to_save: None,
        });
    }

    // --- Tier 3: First encounter — record via TOFU (deferred to commit) ---
    let updated = add_trusted_hash(&manifest, namespace, &current_hash);
    Ok(PendingTrust {
        identity: IdentityInfo {
            hash: current_hash,
            trust_tier: TrustTier::Dev,
            verified: false,
        },
        tofu_conflict: false,
        reason: "First encounter — hash recorded via TOFU".to_string(),
        approved_hashes: Vec::new(),
        manifest_to_save: Some(updated),
    })
}

/// Verify the trust tier of the executable at `exec_path`, recording a
/// first-encounter/Sigstore hash immediately.
///
/// This is the eager convenience form: it runs [`verify_trust_pending`] and
/// commits any pending manifest write before returning. Callers that must not
/// persist a TOFU record until a later step succeeds should use
/// [`verify_trust_pending`] + [`PendingTrust::commit`] instead (see issue #148).
///
/// Pass `"dev"` as `exec_path` to enable dev-mode bypass (skips all hash
/// verification and returns Tier 3 immediately).
pub async fn verify_trust(
    host: &dyn HostPlatform,
    exec_path: &str,
    options: Option<&TrustOptions>,
) -> Result<TrustVerificationResult, VaultError> {
    let pending = verify_trust_pending(host, exec_path, options).await?;
    pending.commit(host).await?;
    Ok(TrustVerificationResult {
        identity: pending.identity,
        tofu_conflict: pending.tofu_conflict,
        reason: pending.reason,
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

        let result = verify_trust(&host, "/usr/bin/test-app", None)
            .await
            .unwrap();
        assert_eq!(result.identity.trust_tier, TrustTier::Dev);
        assert!(!result.identity.verified);
        assert!(!result.tofu_conflict);
        assert!(result.reason.contains("First encounter"));

        // Manifest should have been saved
        let manifest = load_manifest(&host).await.unwrap();
        assert!(is_trusted(
            &manifest,
            "/usr/bin/test-app",
            &result.identity.hash
        ));
    }

    #[tokio::test]
    async fn subsequent_encounter_returns_tier2() {
        let host = MockHost::new();
        host.add_file("/usr/bin/test-app", b"binary-content");

        // First encounter records TOFU
        let first = verify_trust(&host, "/usr/bin/test-app", None)
            .await
            .unwrap();
        assert!(!first.tofu_conflict);

        // Second encounter with same binary should find it in manifest
        let second = verify_trust(&host, "/usr/bin/test-app", None)
            .await
            .unwrap();
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
        verify_trust(&host, "/usr/bin/test-app", None)
            .await
            .unwrap();

        // Change the binary
        host.add_file("/usr/bin/test-app", b"modified-binary");

        // Should detect the TOFU conflict
        let result = verify_trust(&host, "/usr/bin/test-app", None)
            .await
            .unwrap();
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

    /// #148 ordering: the verify phase must record nothing. A first encounter
    /// leaves the manifest unwritten until `commit` is called — proving the
    /// side effect is deferred, not applied during verification.
    #[tokio::test]
    async fn verify_trust_pending_defers_manifest_write() {
        let host = MockHost::new();
        host.add_file("/usr/bin/test-app", b"binary-content");

        let pending = verify_trust_pending(&host, "/usr/bin/test-app", None)
            .await
            .unwrap();
        assert!(!pending.tofu_conflict);
        assert!(pending.reason.contains("First encounter"));

        // Verify phase wrote nothing: the manifest is still empty on disk.
        let before = load_manifest(&host).await.unwrap();
        assert!(
            !is_trusted(&before, "/usr/bin/test-app", &pending.identity.hash),
            "verify phase must not persist the TOFU record"
        );

        // Commit applies the deferred write.
        pending.commit(&host).await.unwrap();
        let after = load_manifest(&host).await.unwrap();
        assert!(is_trusted(
            &after,
            "/usr/bin/test-app",
            &pending.identity.hash
        ));
    }

    /// #148 ordering: a TOFU conflict records nothing. The pending decision
    /// exposes the previously approved hashes and, when committed, must not
    /// persist the conflicting hash.
    #[tokio::test]
    async fn verify_trust_pending_conflict_records_nothing() {
        let host = MockHost::new();
        host.add_file("/usr/bin/test-app", b"original-binary");

        // First encounter, committed.
        let first = verify_trust_pending(&host, "/usr/bin/test-app", None)
            .await
            .unwrap();
        first.commit(&host).await.unwrap();
        let original_hash = first.identity.hash.clone();

        // Change the binary; the new hash conflicts with the recorded one.
        host.add_file("/usr/bin/test-app", b"modified-binary");
        let conflict = verify_trust_pending(&host, "/usr/bin/test-app", None)
            .await
            .unwrap();
        assert!(conflict.tofu_conflict);
        assert_eq!(conflict.approved_hashes, vec![original_hash.clone()]);
        assert_ne!(conflict.identity.hash, original_hash);

        // Committing the conflict writes nothing: the bad hash never lands and
        // the original approval is untouched.
        conflict.commit(&host).await.unwrap();
        let manifest = load_manifest(&host).await.unwrap();
        assert!(is_trusted(&manifest, "/usr/bin/test-app", &original_hash));
        assert!(!is_trusted(
            &manifest,
            "/usr/bin/test-app",
            &conflict.identity.hash
        ));
    }
}
