//! Select and verify the native executable that receives a protected `run`
//! environment. Keep the Unix invocation spelling alongside the canonical
//! verification target so the resolved environment cannot redo PATH lookup.

use std::path::{Path, PathBuf};
use vaultkeeper_core::backend::HostPlatform;
use vaultkeeper_core::errors::{ExecutableTrustRequiredReason, VaultError};
use vaultkeeper_core::identity::TrustOptions;
use vaultkeeper_core::identity::hash::hash_bytes;
use vaultkeeper_core::identity::trust::{VerifiedExecutableIdentity, verify_trust_pending};
use vaultkeeper_core::profile::{EntrySource, LoadedProfile, MinTrust};

/// The selected invocation path and the canonical target approved for it.
pub(super) struct VerifiedRunCommand {
    /// Invoke this selected path directly, without another PATH search.
    pub(super) launch_path: PathBuf,
    /// The target used to establish executable identity.
    canonical_path: PathBuf,
    /// Evidence scoped to the bytes at `canonical_path` when verified.
    pub(super) identity: VerifiedExecutableIdentity,
}

impl VerifiedRunCommand {
    /// Confirm that the verified bytes describe a native launch target and
    /// that the Unix invocation still points to it. Check before resolving
    /// protected entries and again before spawn. Both paths and the file
    /// they identify must remain stable through the OS's subsequent open.
    pub(super) async fn check_launch_target(
        &self,
        host: &dyn HostPlatform,
    ) -> Result<(), VaultError> {
        let bytes = host.read_file(&self.canonical_path).await?;
        let current_hash = hash_bytes(&bytes);
        if current_hash != self.identity.hash() {
            return Err(VaultError::IdentityMismatch {
                message: "Executable changed while resolving the environment".to_string(),
                previous_hash: self.identity.hash().to_string(),
                current_hash,
            });
        }
        #[cfg(unix)]
        {
            if !has_native_executable_header(&bytes) {
                return Err(VaultError::AuthorizationDenied {
                    message: "Protected run requires a native executable. Select and approve the native interpreter explicitly to run a script".to_string(),
                });
            }
            if self.launch_path.canonicalize().ok().as_deref()
                != Some(self.canonical_path.as_path())
            {
                return Err(VaultError::AuthorizationDenied {
                    message: "Executable path changed while resolving the environment".to_string(),
                });
            }
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
            let verified = VerifiedRunCommand {
                launch_path: selected.launch_path,
                canonical_path: selected.canonical_path.clone(),
                identity: identity.clone(),
            };
            #[cfg(unix)]
            verified.check_launch_target(host).await?;
            return Ok(Some(verified));
        }
    }

    Ok(None)
}

/// Recognize the executable families used by native Unix builds. Reject
/// scripts and other file formats because their implicit interpreter would
/// receive the environment without the identity verified for the launch.
/// The OS still decides whether a file with a native header can execute.
#[cfg(unix)]
fn has_native_executable_header(bytes: &[u8]) -> bool {
    #[cfg(target_vendor = "apple")]
    return matches!(
        bytes.get(..4),
        // Thin 32/64-bit Mach-O and universal Mach-O, in either byte order.
        Some(
            b"\xfe\xed\xfa\xce"
                | b"\xce\xfa\xed\xfe"
                | b"\xfe\xed\xfa\xcf"
                | b"\xcf\xfa\xed\xfe"
                | b"\xca\xfe\xba\xbe"
                | b"\xbe\xba\xfe\xca"
                | b"\xca\xfe\xba\xbf"
                | b"\xbf\xba\xfe\xca"
        )
    );

    #[cfg(not(target_vendor = "apple"))]
    return has_native_elf_header(bytes);
}

/// Require the host machine, word size, and byte order so a foreign
/// executable cannot qualify through a transparent emulation handler.
/// The kernel still validates and loads the executable itself.
#[cfg(all(unix, any(not(target_vendor = "apple"), test)))]
fn has_native_elf_header(bytes: &[u8]) -> bool {
    // ELF e_machine assignments from the System V ABI and its supplements.
    let machine = match std::env::consts::ARCH {
        "x86" => 3,
        "mips" | "mips64" | "mips32r6" | "mips64r6" => 8,
        "powerpc" => 20,
        "powerpc64" => 21,
        "s390x" => 22,
        "arm" => 40,
        "sparc64" => 43,
        "x86_64" => 62,
        "aarch64" => 183,
        "riscv32" | "riscv64" => 243,
        "loongarch64" => 258,
        _ => return false,
    };
    let (class, header_size) = if cfg!(target_pointer_width = "64") {
        (2, 64)
    } else {
        (1, 52)
    };
    let data = if cfg!(target_endian = "little") { 1 } else { 2 };
    if bytes.len() < header_size || !bytes.starts_with(&[0x7f, b'E', b'L', b'F', class, data, 1]) {
        return false;
    }

    // e_type must describe ET_EXEC or ET_DYN (which includes PIE binaries).
    let file_type = u16::from_ne_bytes([bytes[16], bytes[17]]);
    let file_machine = u16::from_ne_bytes([bytes[18], bytes[19]]);
    let version = u32::from_ne_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]);
    matches!(file_type, 2 | 3) && file_machine == machine && version == 1
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
    use std::os::unix::fs::symlink;
    use vaultkeeper_core::TrustTier;
    use vaultkeeper_core::identity::hash::hash_executable;
    use vaultkeeper_core::identity::manifest::{add_trusted_hash, save_manifest};
    use vaultkeeper_core::profile::{ProfileDefaults, load_profile_from_str};

    /// An ELF signature can also identify a file that needs an emulator.
    #[test]
    fn native_elf_check_rejects_a_foreign_machine() {
        // An inert ELF header with the reserved EM_NONE machine identifier.
        let mut header = [0; 64];
        header[..4].copy_from_slice(b"\x7fELF");
        header[4] = if cfg!(target_pointer_width = "64") {
            2
        } else {
            1
        };
        header[5] = if cfg!(target_endian = "little") { 1 } else { 2 };
        header[6] = 1;
        header[16..18].copy_from_slice(&2_u16.to_ne_bytes());
        header[20..24].copy_from_slice(&1_u32.to_ne_bytes());

        assert!(!has_native_elf_header(&header));
    }

    /// A verified alias must still name the approved target at launch time.
    #[tokio::test]
    async fn verified_alias_rejects_a_changed_launch_target() {
        let dir = tempfile::tempdir().unwrap();
        let host = NativeHostPlatform::new(dir.path().to_path_buf());
        let original = dir.path().join("original");
        let replacement = dir.path().join("replacement");
        let alias = dir.path().join("alias");
        for path in [&original, &replacement] {
            fs::copy("/bin/sh", path).unwrap();
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
