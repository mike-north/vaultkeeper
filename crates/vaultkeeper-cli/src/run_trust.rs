//! Select and verify the executable for a protected native `run`. Keeping the
//! absolute target with its verification evidence makes the launch independent
//! of later PATH lookup, including PATH supplied by the resolved environment.

use std::path::{Path, PathBuf};
use vaultkeeper_core::backend::HostPlatform;
use vaultkeeper_core::errors::{ExecutableTrustRequiredReason, VaultError};
use vaultkeeper_core::identity::TrustOptions;
use vaultkeeper_core::identity::hash::hash_executable;
use vaultkeeper_core::identity::trust::{VerifiedExecutableIdentity, verify_trust_pending};
use vaultkeeper_core::profile::{EntrySource, LoadedProfile, MinTrust};

/// The canonical launch target paired with the evidence supplied to the resolver.
pub(super) struct VerifiedRunCommand {
    /// Use this absolute path for launch even when the caller supplied a name.
    pub(super) path: PathBuf,
    /// Evidence scoped to the bytes at `path` when verified.
    pub(super) identity: VerifiedExecutableIdentity,
}

impl VerifiedRunCommand {
    /// Detect changes to the target during materialization. The directory and
    /// executable must remain stable through the OS's subsequent pathname open.
    pub(super) async fn check_digest(&self, host: &dyn HostPlatform) -> Result<(), VaultError> {
        let current_hash = hash_executable(host, &self.path).await?;
        if current_hash == self.identity.hash() {
            return Ok(());
        }
        Err(VaultError::IdentityMismatch {
            message: "Executable changed while resolving the environment".to_string(),
            previous_hash: self.identity.hash().to_string(),
            current_hash,
        })
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
    let (selected, path) = select_executable(command, explicit).ok_or_else(|| {
        VaultError::ExecutableTrustRequired {
            message: format!("Could not resolve executable {command:?} for minTrust verification"),
            reason: ExecutableTrustRequiredReason::MissingChoice,
        }
    })?;
    let executable = path
        .to_str()
        .ok_or_else(|| VaultError::ExecutableTrustRequired {
            message: "minTrust verification requires a UTF-8 executable path".to_string(),
            reason: ExecutableTrustRequiredReason::MissingChoice,
        })?;

    // The manifest is keyed by the path spelling used at approval. Accept
    // approval for the canonical target, the selected absolute name (which
    // may be a symlink), or the explicit spelling used by an existing caller.
    // Each lookup verifies the bytes at the same absolute launch target.
    let selected = selected.to_str().filter(|name| *name != executable);
    let requested = explicit
        .then_some(command)
        .filter(|name| *name != executable && Some(*name) != selected);
    for namespace in [Some(executable), selected, requested]
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
                path: path.clone(),
                identity: identity.clone(),
            }));
        }
    }

    Ok(None)
}

/// Resolve an explicit path or the first executable on the parent's PATH.
/// Retain the absolute pre-canonical spelling for existing manifest entries.
fn select_executable(command: &str, explicit: bool) -> Option<(PathBuf, PathBuf)> {
    if explicit {
        return executable_candidate(PathBuf::from(command));
    }
    if command.is_empty() {
        return None;
    }

    let search_path = std::env::var_os("PATH")
        .or_else(|| cfg!(unix).then(|| std::ffi::OsString::from("/usr/bin:/bin")))?;
    std::env::split_paths(&search_path)
        .find_map(|directory| executable_candidate(directory.join(command)))
}

/// Ignore directories and executables the current user cannot launch. On
/// Windows require an actual `.exe` so the launcher cannot substitute a
/// command interpreter for a batch file after verification.
fn executable_candidate(candidate: PathBuf) -> Option<(PathBuf, PathBuf)> {
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

    let selected = std::path::absolute(candidate).ok()?;
    let canonical = selected.canonicalize().ok()?;
    if !canonical.is_file() {
        return None;
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let path = std::ffi::CString::new(canonical.as_os_str().as_bytes()).ok()?;
        // SAFETY: `path` points to a live, NUL-terminated C string.
        if unsafe { libc::access(path.as_ptr(), libc::X_OK) } != 0 {
            return None;
        }
    }
    #[cfg(windows)]
    if !has_exe_extension(&canonical) {
        return None;
    }

    Some((selected, canonical))
}

/// Windows recognizes the native executable extension case-insensitively.
#[cfg(windows)]
fn has_exe_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("exe"))
}
