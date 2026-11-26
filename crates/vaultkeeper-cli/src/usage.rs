//! Persists finite-use secret token admissions across native CLI invocations.
//! The ledger stores counts keyed by a hash of the authenticated JTI.

use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::time::Instant;
use vaultkeeper_core::backend::HostPlatform;
use vaultkeeper_core::errors::VaultError;
use vaultkeeper_core::jwe::extract_kid;
use vaultkeeper_core::keys::{KeyManager, KeyMaterial, load_key_state};
use vaultkeeper_core::types::VaultClaims;

use crate::host::create_dir_all_secure;

#[cfg(test)]
mod tests;

/// Limit how long a stalled writer can block a launcher.
const LOCK_WAIT: Duration = Duration::from_secs(10);

/// Stable lock file shared by native admissions and encryption-key changes.
const KEY_ADMISSION_LOCK: &str = ".token-admission.lock";

/// Admissions for different tokens can share the key-state read lock. Usage
/// updates for the same JTI and changes to the encryption keys are exclusive.
enum LockAccess {
    Shared,
    Exclusive,
}

/// Hold across native key initialization and mutation. Keep the lock outside
/// the usage ledger so an unreadable ledger cannot prevent key revocation.
pub(crate) async fn lock_key_changes(config_dir: &Path) -> Result<File, VaultError> {
    create_dir_all_secure(config_dir)
        .map_err(|error| fs_error(config_dir, "create config directory for key lock", error))?;
    acquire_lock(&config_dir.join(KEY_ADMISSION_LOCK), LockAccess::Exclusive).await
}

#[derive(Deserialize, Serialize)]
struct UsageState {
    uses: u64,
}

/// Reserve one use of an authenticated token before its handle can expose the
/// secret. The key lookup uses the same key manager that authorized the token.
/// A committed admission spends the use even if launching the child fails.
pub(crate) async fn reserve(
    host: &dyn HostPlatform,
    token: &str,
    claims: &VaultClaims,
    authorized_keys: &mut KeyManager,
) -> Result<(), VaultError> {
    let Some(limit) = claims.use_limit else {
        return Ok(());
    };

    let config_dir = host.config_dir();
    let directory = prepare_directory(config_dir)?;
    let fingerprint = vaultkeeper_core::identity::hash::hash_bytes(claims.jti.as_bytes());
    let state_path = directory.join(format!("{fingerprint}.json"));
    let lock_path = directory.join(format!("{fingerprint}.lock"));
    let _lock = acquire_lock(&lock_path, LockAccess::Exclusive).await?;

    // Take the per-token lock first so a launcher waiting for its budget
    // never delays key changes. Hold the shared key lock through the durable
    // commit to order admission against native rotation and revocation.
    let _key_lock = acquire_lock(&config_dir.join(KEY_ADMISSION_LOCK), LockAccess::Shared).await?;

    check_key_eligibility(host, token, authorized_keys).await?;

    // The token can expire while admission waits or reads key state.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if now >= claims.exp {
        return Err(VaultError::TokenExpired {
            message: format!("Token expired at {} (now: {now})", claims.exp),
            can_refresh: false,
        });
    }

    let uses = read_usage(&state_path)?;
    if uses >= limit {
        return Err(VaultError::UsageLimitExceeded {
            message: format!("Token usage limit of {limit} exceeded (used: {uses})"),
        });
    }

    // Acquire every handle required for durability before committing the count.
    #[cfg(unix)]
    let sync_directories = [directory.as_path(), config_dir]
        .map(|path| {
            File::open(path).map_err(|error| fs_error(path, "open token usage directory", error))
        })
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;

    write_usage(&state_path, UsageState { uses: uses + 1 })?;

    // Persist both directory entries on Unix, including on first use. If
    // syncing fails after rename, fail closed and keep the committed count.
    #[cfg(unix)]
    for (path, dir) in [directory.as_path(), config_dir]
        .into_iter()
        .zip(sync_directories)
    {
        dir.sync_all()
            .map_err(|error| fs_error(path, "sync token usage directory", error))?;
    }
    Ok(())
}

/// Check the key that authenticated the protected JWE header against the
/// persisted key state without decrypting the secret again. A token with no
/// header key ID is eligible only under the current key, as in core authorization.
async fn check_key_eligibility(
    host: &dyn HostPlatform,
    token: &str,
    authorized_keys: &mut KeyManager,
) -> Result<(), VaultError> {
    let kid = extract_kid(token)?;
    let revoked = || VaultError::KeyRevoked {
        message: "Token encryption key is no longer eligible".to_string(),
    };
    let authorized_key = match kid.as_deref() {
        Some(id) => authorized_keys
            .find_key_by_id(id)
            .map(|(key, _)| key)
            .ok_or_else(revoked)?,
        None => authorized_keys.get_current_key()?,
    };

    // IDs select keys, but only the same key material can authenticate this
    // token. The loader includes a previous key only during rotation grace.
    let matches = |key: &KeyMaterial| key.id == authorized_key.id && key.key == authorized_key.key;
    let current = load_key_state(host).await?.ok_or_else(revoked)?;
    if matches(&current.current)
        || (kid.is_some() && current.previous.as_ref().is_some_and(matches))
    {
        Ok(())
    } else {
        Err(revoked())
    }
}

/// Keep the ledger under the same trusted config path as the keys. On
/// Windows the ledger inherits the config tree's access control.
fn prepare_directory(config_dir: &Path) -> Result<PathBuf, VaultError> {
    #[cfg(unix)]
    {
        let config = fs::metadata(config_dir)
            .map_err(|error| fs_error(config_dir, "inspect config directory", error))?;
        if !config.is_dir() || !is_owner_controlled(&config, 0o022) {
            return Err(unsafe_storage(
                config_dir,
                "Token usage requires an owner-controlled config directory",
            ));
        }
    }

    let directory = config_dir.join("token-usage");
    create_dir_all_secure(&directory)
        .map_err(|error| fs_error(&directory, "create token usage directory", error))?;
    let metadata = fs::symlink_metadata(&directory)
        .map_err(|error| fs_error(&directory, "inspect token usage directory", error))?;
    if !metadata.is_dir() {
        return Err(unsafe_storage(
            &directory,
            "Expected a real, owner-only token usage directory",
        ));
    }
    #[cfg(unix)]
    if !is_owner_controlled(&metadata, 0o077) {
        return Err(unsafe_storage(
            &directory,
            "Expected an owner-only token usage directory",
        ));
    }
    Ok(directory)
}

#[cfg(unix)]
fn is_owner_controlled(metadata: &fs::Metadata, denied_mode: u32) -> bool {
    use std::os::unix::fs::MetadataExt;

    // SAFETY: geteuid takes no arguments and has no preconditions.
    metadata.uid() == unsafe { libc::geteuid() } && metadata.mode() & denied_mode == 0
}

/// Writers leave the lock file in place so contenders share one lock across
/// replacements of the counter. The OS releases the lock on process exit.
async fn acquire_lock(path: &Path, access: LockAccess) -> Result<File, VaultError> {
    regular_file_exists(path)?;
    let lock = private_file_options()
        .read(true)
        .create(true)
        .truncate(false)
        .open(path)
        .map_err(|error| fs_error(path, "open token usage lock", error))?;
    let deadline = Instant::now() + LOCK_WAIT;
    loop {
        let result = match access {
            LockAccess::Shared => lock.try_lock_shared(),
            LockAccess::Exclusive => lock.try_lock(),
        };
        match result {
            Ok(()) => return Ok(lock),
            Err(TryLockError::Error(error)) => {
                return Err(fs_error(path, "acquire token usage lock", error));
            }
            Err(TryLockError::WouldBlock) if Instant::now() >= deadline => {
                return Err(fs_error(
                    path,
                    "acquire token usage lock",
                    io::ErrorKind::TimedOut.into(),
                ));
            }
            Err(TryLockError::WouldBlock) => tokio::time::sleep(Duration::from_millis(10)).await,
        }
    }
}

fn read_usage(path: &Path) -> Result<u64, VaultError> {
    if !regular_file_exists(path)? {
        return Ok(0);
    }
    let bytes = fs::read(path).map_err(|error| fs_error(path, "read token usage state", error))?;
    match serde_json::from_slice::<UsageState>(&bytes) {
        Ok(state) if state.uses > 0 => Ok(state.uses),
        // Serde diagnostics can echo input from a damaged file.
        _ => Err(VaultError::InvalidToken {
            message: format!("Token usage state {} is corrupt", path.display()),
        }),
    }
}

/// Flush the replacement before making it visible. An interrupted writer's
/// temporary file carries no committed reservations.
fn write_usage(path: &Path, state: UsageState) -> Result<(), VaultError> {
    let temporary = path.with_extension("json.tmp");
    match fs::remove_file(&temporary) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(fs_error(
                &temporary,
                "discard partial token usage state",
                error,
            ));
        }
    }
    let bytes = serde_json::to_vec(&state)
        .map_err(|_| VaultError::Other("Could not serialize token usage state".to_string()))?;
    let mut file = private_file_options()
        .create_new(true)
        .open(&temporary)
        .map_err(|error| fs_error(&temporary, "create token usage state", error))?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| fs_error(&temporary, "write token usage state", error))?;
    drop(file);
    fs::rename(&temporary, path).map_err(|error| fs_error(path, "install token usage state", error))
}

fn regular_file_exists(path: &Path) -> Result<bool, VaultError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() => {
            #[cfg(unix)]
            if !is_owner_controlled(&metadata, 0o077) {
                return Err(unsafe_storage(
                    path,
                    "Expected an owner-only token usage file",
                ));
            }
            Ok(true)
        }
        Ok(_) => Err(unsafe_storage(path, "Expected a regular token usage file")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(fs_error(path, "inspect token usage file", error)),
    }
}

fn private_file_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
}

fn fs_error(path: &Path, operation: &str, error: io::Error) -> VaultError {
    VaultError::Filesystem {
        message: format!("Could not {operation} at {}: {error}", path.display()),
        path: path.display().to_string(),
        permission: "token usage".to_string(),
        code: None,
    }
}

fn unsafe_storage(path: &Path, message: &str) -> VaultError {
    fs_error(
        path,
        "validate settings for token usage",
        io::Error::new(io::ErrorKind::PermissionDenied, message),
    )
}
