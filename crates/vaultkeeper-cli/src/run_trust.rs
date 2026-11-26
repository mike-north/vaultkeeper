//! Select and verify the executable for a protected native `run`. Preserve the
//! Unix invocation spelling alongside its canonical verification target. The
//! selected launch path bypasses PATH lookup in the resolved environment.

use std::path::{Path, PathBuf};
use vaultkeeper_core::backend::HostPlatform;
use vaultkeeper_core::errors::{ExecutableTrustRequiredReason, VaultError};
use vaultkeeper_core::identity::TrustOptions;
use vaultkeeper_core::identity::hash::hash_executable;
use vaultkeeper_core::identity::trust::{VerifiedExecutableIdentity, verify_trust_pending};
use vaultkeeper_core::profile::{EntrySource, LoadedProfile, MinTrust};

/// The selected invocation path and the canonical target approved for it.
pub(super) struct VerifiedRunCommand {
    /// Use this path directly so interpreters receive the selected script name.
    pub(super) launch_path: PathBuf,
    /// The target used to establish executable identity.
    canonical_path: PathBuf,
    /// Evidence scoped to the bytes at `canonical_path` when verified.
    pub(super) identity: VerifiedExecutableIdentity,
}

impl VerifiedRunCommand {
    /// Recheck the approved bytes, then confirm that the Unix invocation
    /// still points to them. Both paths must remain stable through the OS's
    /// subsequent open and, for scripts, the interpreter's open.
    pub(super) async fn check_launch_target(
        &self,
        host: &dyn HostPlatform,
    ) -> Result<(), VaultError> {
        let current_hash = hash_executable(host, &self.canonical_path).await?;
        if current_hash != self.identity.hash() {
            return Err(VaultError::IdentityMismatch {
                message: "Executable changed while resolving the environment".to_string(),
                previous_hash: self.identity.hash().to_string(),
                current_hash,
            });
        }
        #[cfg(unix)]
        if self.launch_path.canonicalize().ok().as_deref() != Some(self.canonical_path.as_path()) {
            return Err(VaultError::AuthorizationDenied {
                message: "Executable path changed while resolving the environment".to_string(),
            });
        }
        Ok(())
    }
}

/// Inspect the actual profile after applying overlays. Plans without a
/// protected secret source keep the host's ordinary command launch semantics.
/// A protected plan uses a read-only trust decision. In particular, a failed
/// run cannot register a first encounter for a future run.
pub(super) async fn verify_run_command(
    host: &dyn HostPlatform,
    profile: &LoadedProfile,
    command: &str,
) -> Result<Option<VerifiedRunCommand>, VaultError> {
    if !profile.entries.iter().any(|(_, entry)| {
        matches!(entry.source, EntrySource::Secret(_)) && entry.min_trust > MinTrust::Unverified
    }) {
        return Ok(None);
    }

    let explicit = command.contains('/')
        || command.contains(std::path::MAIN_SEPARATOR)
        || Path::new(command).components().count() > 1;
    let selected = select_executable(command, explicit).ok_or_else(|| {
        VaultError::ExecutableTrustRequired {
            message: format!("Could not resolve executable {command:?} for minTrust verification"),
            reason: ExecutableTrustRequiredReason::MissingChoice,
        }
    })?;
    let executable =
        selected
            .canonical_path
            .to_str()
            .ok_or_else(|| VaultError::ExecutableTrustRequired {
                message: "minTrust verification requires a UTF-8 executable path".to_string(),
                reason: ExecutableTrustRequiredReason::MissingChoice,
            })?;

    // The manifest is keyed by the path spelling used at approval. Accept
    // approval for the canonical target, the selected absolute name (which
    // may be a symlink), or the explicit spelling used by an existing caller.
    // Each lookup verifies the bytes at the same canonical target.
    let absolute = selected
        .absolute_path
        .to_str()
        .filter(|name| *name != executable);
    let requested = explicit
        .then_some(command)
        .filter(|name| *name != executable && Some(*name) != absolute);
    for namespace in [Some(executable), absolute, requested]
        .into_iter()
        .flatten()
    {
        let options = TrustOptions {
            namespace: Some(namespace.to_string()),
            ..Default::default()
        };
        let pending = verify_trust_pending(host, executable, Some(&options)).await?;
        if let Some(identity) = pending.verified_identity() {
            return Ok(Some(VerifiedRunCommand {
                launch_path: selected.launch_path,
                canonical_path: selected.canonical_path.clone(),
                identity: identity.clone(),
            }));
        }
    }

    Ok(None)
}

/// The path passed to the OS, its absolute spelling for manifest lookup, and
/// the canonical target whose bytes establish identity.
struct SelectedExecutable {
    launch_path: PathBuf,
    absolute_path: PathBuf,
    canonical_path: PathBuf,
}

/// Resolve an explicit path or the first executable on the parent's PATH.
fn select_executable(command: &str, explicit: bool) -> Option<SelectedExecutable> {
    if explicit {
        return executable_candidate(PathBuf::from(command));
    }
    if command.is_empty() {
        return None;
    }

    let search_path = std::env::var_os("PATH")
        .or_else(|| cfg!(unix).then(|| std::ffi::OsString::from("/usr/bin:/bin")))?;
    std::env::split_paths(&search_path).find_map(|directory| {
        // An empty Unix PATH component means the current directory. Keep a
        // slash in the launch path so spawning it cannot search PATH again.
        #[cfg(unix)]
        let directory = if directory.as_os_str().is_empty() {
            PathBuf::from(".")
        } else {
            directory
        };
        executable_candidate(directory.join(command))
    })
}

/// Ignore directories and executables the current user cannot launch. On
/// Windows require an actual `.exe` so the launcher cannot substitute a
/// command interpreter for a batch file after verification.
fn executable_candidate(candidate: PathBuf) -> Option<SelectedExecutable> {
    #[cfg(windows)]
    let candidate = {
        let mut candidate = candidate;
        if candidate.extension().is_none() {
            candidate.set_extension("exe");
        }
        if !has_exe_extension(&candidate) {
            return None;
        }
        candidate
    };

    let absolute_path = std::path::absolute(&candidate).ok()?;
    let canonical_path = absolute_path.canonicalize().ok()?;
    if !canonical_path.is_file() {
        return None;
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let path = std::ffi::CString::new(canonical_path.as_os_str().as_bytes()).ok()?;
        // SAFETY: `path` points to a live, NUL-terminated C string.
        if unsafe { libc::access(path.as_ptr(), libc::X_OK) } != 0 {
            return None;
        }
    }
    #[cfg(windows)]
    if !has_exe_extension(&canonical_path) {
        return None;
    }

    Some(SelectedExecutable {
        #[cfg(unix)]
        launch_path: candidate,
        #[cfg(not(unix))]
        launch_path: canonical_path.clone(),
        absolute_path,
        canonical_path,
    })
}

/// Windows recognizes the native executable extension case-insensitively.
#[cfg(windows)]
fn has_exe_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("exe"))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::host::NativeHostPlatform;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use vaultkeeper_core::TrustTier;
    use vaultkeeper_core::identity::manifest::{add_trusted_hash, save_manifest};
    use vaultkeeper_core::profile::{ProfileDefaults, load_profile_from_str};

    /// A verified alias must still name the approved target at launch time.
    #[tokio::test]
    async fn verified_alias_rejects_a_changed_launch_target() {
        let dir = tempfile::tempdir().unwrap();
        let host = NativeHostPlatform::new(dir.path().to_path_buf());
        let original = dir.path().join("original");
        let replacement = dir.path().join("replacement");
        let alias = dir.path().join("alias");
        for path in [&original, &replacement] {
            fs::write(path, b"#!/bin/sh\nexit 0\n").unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        symlink(&original, &alias).unwrap();
        let digest = hash_executable(&host, &original).await.unwrap();
        let approved_path = original.canonicalize().unwrap();
        let manifest = add_trusted_hash(
            &Default::default(),
            approved_path.to_str().unwrap(),
            &digest,
        );
        save_manifest(&host, &manifest).await.unwrap();
        let profile = load_profile_from_str(
            r#"{"version":1,"name":"registry","entries":{
                "SECRET":{"secret":"fixture","materialize":"secret","minTrust":"registry"}
            }}"#,
            &ProfileDefaults {
                ttl_seconds: 60,
                trust_tier: TrustTier::Dev,
            },
        )
        .unwrap();
        let verified = verify_run_command(&host, &profile, alias.to_str().unwrap())
            .await
            .unwrap()
            .unwrap();
        verified.check_launch_target(&host).await.unwrap();

        // Even identical bytes at a new path lack approval for that target.
        fs::remove_file(&alias).unwrap();
        symlink(&replacement, &alias).unwrap();
        assert!(matches!(
            verified.check_launch_target(&host).await,
            Err(VaultError::AuthorizationDenied { .. })
        ));
    }
}
