//! Persists finite-use secret token admissions across native CLI invocations.
//! The ledger stores counts keyed by a hash of the authenticated JTI.

use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::time::Instant;
use vaultkeeper_core::errors::VaultError;
use vaultkeeper_core::types::VaultClaims;

use crate::host::create_dir_all_secure;

/// Limit how long a stalled writer can block a launcher.
const LOCK_WAIT: Duration = Duration::from_secs(10);

#[derive(Deserialize, Serialize)]
struct UsageState {
    uses: u64,
}

/// Reserve one use after core authorization and before reading the secret.
/// A committed admission spends the use even if launching the child fails.
pub(crate) async fn reserve(config_dir: &Path, claims: &VaultClaims) -> Result<(), VaultError> {
    let Some(limit) = claims.use_limit else {
        return Ok(());
    };

    let directory = prepare_directory(config_dir)?;
    let fingerprint = vaultkeeper_core::identity::hash::hash_bytes(claims.jti.as_bytes());
    let state_path = directory.join(format!("{fingerprint}.json"));
    let lock_path = directory.join(format!("{fingerprint}.lock"));
    let _lock = acquire_lock(&lock_path).await?;

    // Core validated the token, but it can expire while waiting for the lock.
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

    write_usage(&state_path, UsageState { uses: uses + 1 })?;

    // Persist both directory entries on Unix, including on first use. If
    // syncing fails after rename, fail closed and keep the committed count.
    #[cfg(unix)]
    for path in [directory.as_path(), config_dir] {
        File::open(path)
            .and_then(|dir| dir.sync_all())
            .map_err(|error| fs_error(path, "sync token usage directory", error))?;
    }
    Ok(())
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
async fn acquire_lock(path: &Path) -> Result<File, VaultError> {
    regular_file_exists(path)?;
    let lock = private_file_options()
        .read(true)
        .create(true)
        .truncate(false)
        .open(path)
        .map_err(|error| fs_error(path, "open token usage lock", error))?;
    let deadline = Instant::now() + LOCK_WAIT;
    loop {
        match lock.try_lock() {
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
