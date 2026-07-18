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
use super::types::{IdentityInfo, TrustOptions, TrustVerificationResult};
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
    /// The namespace/hash entry staged for [`PendingTrust::commit`] to merge into
    /// the on-disk manifest, or `None` when this decision records nothing (a
    /// registry match, the dev bypass, or a TOFU conflict).
    ///
    /// Deliberately *not* a whole-manifest snapshot: verification and commit are
    /// not atomic, so persisting a snapshot captured back in
    /// [`verify_trust_pending`] would clobber any entry a concurrent process
    /// wrote in between. `commit` reloads the current on-disk manifest and merges
    /// just this entry into it instead (issue #209; mirrors the TS fix in #204).
    pending_write: Option<(String, String)>,
}

impl PendingTrust {
    /// Persist the pending trust-manifest write, if any — staged by a Tier-1
    /// (Sigstore) approval or a Tier-3 (TOFU first-encounter) recording. A
    /// no-op when there is nothing to record.
    ///
    /// Call this only after the overall operation has otherwise succeeded (e.g.
    /// the token has been minted) so a failure never leaves a premature
    /// trust-manifest record behind (issue #148).
    ///
    /// Verification and commit are not atomic — another process can write to the
    /// manifest in between (e.g. approving a different executable, or the same
    /// one). To avoid clobbering that concurrent write, this reloads the manifest
    /// from disk immediately before saving and re-classifies the staged
    /// `(namespace, hash)` entry against the *current* state, rather than
    /// persisting a snapshot captured back in [`verify_trust_pending`] (issue
    /// #209):
    ///
    /// - Already trusted (e.g. a concurrent commit for the same executable
    ///   landed first) — a no-op; skipping the redundant `save_manifest` avoids
    ///   unnecessary I/O and shrinks the window for a last-writer-wins race.
    /// - The namespace has approved hashes that do **not** include the staged
    ///   one — a concurrent process recorded a *different* executable for this
    ///   namespace in the window since verification. Merging anyway would
    ///   silently approve a second hash for one namespace, bypassing the
    ///   TOFU-conflict record-nothing rule enforced at verify time (issue
    ///   #148). This re-classifies as a conflict: returns
    ///   [`VaultError::IdentityMismatch`] and writes nothing.
    /// - The namespace has no entry yet — merges the staged entry in, as
    ///   before.
    pub async fn commit(&self, host: &dyn HostPlatform) -> Result<(), VaultError> {
        if let Some((namespace, hash)) = &self.pending_write {
            let current = load_manifest(host).await?;
            match current.get(namespace) {
                Some(existing) if existing.hashes.iter().any(|h| h == hash) => {
                    return Ok(());
                }
                Some(existing) if !existing.hashes.is_empty() => {
                    let previous_hash = existing
                        .hashes
                        .last()
                        .cloned()
                        .unwrap_or_else(|| hash.clone());
                    return Err(VaultError::IdentityMismatch {
                        message: "Executable hash changed — re-approval required".to_string(),
                        previous_hash,
                        current_hash: hash.clone(),
                    });
                }
                _ => {}
            }
            let merged = add_trusted_hash(&current, namespace, hash);
            save_manifest(host, &merged).await?;
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
            pending_write: None,
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
            return Ok(PendingTrust {
                identity: IdentityInfo {
                    hash: current_hash.clone(),
                    trust_tier: TrustTier::Sigstore,
                    verified: true,
                },
                tofu_conflict: false,
                reason: "Sigstore bundle verified".to_string(),
                approved_hashes: Vec::new(),
                pending_write: Some((namespace.to_string(), current_hash)),
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
            pending_write: None,
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
            pending_write: None,
        });
    }

    // --- Tier 3: First encounter — record via TOFU (deferred to commit) ---
    Ok(PendingTrust {
        identity: IdentityInfo {
            hash: current_hash.clone(),
            trust_tier: TrustTier::Dev,
            verified: false,
        },
        tofu_conflict: false,
        reason: "First encounter — hash recorded via TOFU".to_string(),
        approved_hashes: Vec::new(),
        pending_write: Some((namespace.to_string(), current_hash)),
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
    use crate::backend::{ExecOptions, ExecOutput, Platform};
    use async_trait::async_trait;
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A mock HostPlatform that stores files in memory.
    struct MockHost {
        files: Mutex<HashMap<PathBuf, Vec<u8>>>,
        config_dir: PathBuf,
        /// Number of `write_file` calls observed, for tests asserting a redundant
        /// save was skipped rather than merely idempotent.
        write_count: AtomicUsize,
    }

    impl MockHost {
        fn new() -> Self {
            Self {
                files: Mutex::new(HashMap::new()),
                config_dir: PathBuf::from("/mock/config"),
                write_count: AtomicUsize::new(0),
            }
        }

        fn add_file(&self, path: &str, content: &[u8]) {
            self.files
                .lock()
                .unwrap()
                .insert(PathBuf::from(path), content.to_vec());
        }

        fn write_count(&self) -> usize {
            self.write_count.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl HostPlatform for MockHost {
        async fn exec(
            &self,
            _cmd: &str,
            _args: &[&str],
            _options: ExecOptions<'_>,
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
            self.write_count.fetch_add(1, Ordering::SeqCst);
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

    /// Issue #209 regression (mirrors PR #204's TS interleaving test): committing
    /// a `PendingTrust` must merge into the manifest's *current* on-disk state,
    /// not overwrite it with the snapshot captured back in
    /// `verify_trust_pending`. Before the fix, `PendingTrust` staged a whole
    /// merged-manifest snapshot and `commit` saved that snapshot directly —
    /// silently discarding a concurrent process's write to a different
    /// namespace that landed between verify and commit. This test fails against
    /// pre-fix code: `other-tool`'s entry would be missing after `commit`.
    #[tokio::test]
    async fn commit_merges_with_concurrent_manifest_write_instead_of_clobbering_it() {
        let host = MockHost::new();
        host.add_file("/usr/bin/my-tool", b"binary-content-v1");

        let pending = verify_trust_pending(&host, "/usr/bin/my-tool", None)
            .await
            .unwrap();

        // Simulate a concurrent process approving a different executable
        // between our verify phase and our commit.
        let concurrent_manifest = load_manifest(&host).await.unwrap();
        let with_concurrent_entry =
            add_trusted_hash(&concurrent_manifest, "other-tool", "concurrent-hash");
        save_manifest(&host, &with_concurrent_entry).await.unwrap();

        pending.commit(&host).await.unwrap();

        // Both the concurrent entry and our staged entry must survive.
        let manifest = load_manifest(&host).await.unwrap();
        assert!(is_trusted(&manifest, "other-tool", "concurrent-hash"));
        assert!(is_trusted(
            &manifest,
            "/usr/bin/my-tool",
            &pending.identity.hash
        ));
    }

    /// `commit` must not re-save the manifest when the staged hash is already
    /// trusted in the freshly reloaded state (e.g. a concurrent commit for the
    /// same executable landed first): re-saving identical content is wasted I/O
    /// and needlessly widens the last-writer-wins window. Asserted via the host's
    /// write count rather than manifest content, since a redundant save would be
    /// content-idempotent but still a real (avoidable) write.
    #[tokio::test]
    async fn commit_skips_save_when_staged_entry_already_trusted() {
        let host = MockHost::new();
        host.add_file("/usr/bin/my-tool", b"binary-content-v1");

        let pending = verify_trust_pending(&host, "/usr/bin/my-tool", None)
            .await
            .unwrap();

        // Simulate a concurrent commit for the same executable landing first —
        // the staged (namespace, hash) is already present by the time our
        // commit reloads the manifest.
        let concurrent_manifest = load_manifest(&host).await.unwrap();
        let already_committed = add_trusted_hash(
            &concurrent_manifest,
            "/usr/bin/my-tool",
            &pending.identity.hash,
        );
        save_manifest(&host, &already_committed).await.unwrap();
        let writes_before_commit = host.write_count();

        pending.commit(&host).await.unwrap();

        assert_eq!(
            host.write_count(),
            writes_before_commit,
            "commit must not write when the staged entry is already trusted"
        );
    }

    /// Issue #213 review follow-up: a *late* TOFU conflict. If a concurrent
    /// process records a DIFFERENT hash for the SAME namespace in the window
    /// between verify and commit, blindly merging the staged hash would
    /// silently approve a second hash for one namespace — bypassing the
    /// TOFU-conflict record-nothing rule enforced at verify time (issue #148).
    /// `commit` must re-classify against the freshly reloaded manifest and
    /// refuse: return `IdentityMismatch` and write nothing.
    #[tokio::test]
    async fn commit_refuses_when_a_concurrent_process_recorded_a_different_hash_for_the_same_namespace()
     {
        let host = MockHost::new();
        host.add_file("/usr/bin/my-tool", b"binary-content-v1");

        let pending = verify_trust_pending(&host, "/usr/bin/my-tool", None)
            .await
            .unwrap();
        let staged_hash = pending.identity.hash.clone();

        // Simulate a concurrent process recording a DIFFERENT hash for the
        // SAME namespace before our commit reloads the manifest.
        let concurrent_manifest = load_manifest(&host).await.unwrap();
        let with_other_hash = add_trusted_hash(
            &concurrent_manifest,
            "/usr/bin/my-tool",
            "concurrent-hash-b",
        );
        save_manifest(&host, &with_other_hash).await.unwrap();

        let err = pending.commit(&host).await.unwrap_err();
        match err {
            VaultError::IdentityMismatch {
                previous_hash,
                current_hash,
                ..
            } => {
                assert_eq!(previous_hash, "concurrent-hash-b");
                assert_eq!(current_hash, staged_hash);
            }
            other => panic!("expected IdentityMismatch, got {other:?}"),
        }

        // Nothing was written beyond the concurrent entry: our staged hash
        // never landed, and the namespace still has only one approved hash.
        let manifest = load_manifest(&host).await.unwrap();
        assert!(is_trusted(
            &manifest,
            "/usr/bin/my-tool",
            "concurrent-hash-b"
        ));
        assert!(!is_trusted(&manifest, "/usr/bin/my-tool", &staged_hash));
        assert_eq!(
            manifest["/usr/bin/my-tool"].hashes,
            vec!["concurrent-hash-b".to_string()]
        );
    }
}
