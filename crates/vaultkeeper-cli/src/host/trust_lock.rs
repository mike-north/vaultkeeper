use std::fs;
use std::io::{self, ErrorKind};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use vaultkeeper_core::VaultError;

/// Owns the marker in a directory published atomically by rename. The
/// Node hosts use the same protocol in vaultkeeper-wasm/host/trust-lock.js.
pub(super) struct TrustLock {
    path: PathBuf,
    owner: String,
}

impl Drop for TrustLock {
    fn drop(&mut self) {
        if fs::remove_file(self.path.join(&self.owner)).is_ok() {
            // A successor always arrives as a nonempty directory.
            let _ = fs::remove_dir(&self.path);
        }
    }
}

pub(super) async fn acquire(path: &Path, nonce: &str) -> Result<TrustLock, VaultError> {
    acquire_at(path, nonce)
        .await
        .map_err(|error| VaultError::Filesystem {
            message: format!("Failed to lock {}: {error}", path.display()),
            path: path.display().to_string(),
            permission: "lock".to_string(),
            code: None,
        })
}

/// Cleans up the private candidate on errors and on cancellation during retry.
struct Candidate(PathBuf, String);

impl Drop for Candidate {
    fn drop(&mut self) {
        let _ = fs::remove_file(self.0.join(&self.1));
        let _ = fs::remove_dir(&self.0);
    }
}

async fn acquire_at(path: &Path, nonce: &str) -> io::Result<TrustLock> {
    if !is_nonce(nonce) {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "invalid trust lock nonce",
        ));
    }
    let owner = format!("{}-{nonce}", std::process::id());
    let candidate = path.with_extension(format!("lock.{owner}"));
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::create_dir(&candidate)?;
    let candidate = Candidate(candidate, owner);
    fs::File::create_new(candidate.0.join(&candidate.1))?;
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match fs::rename(&candidate.0, path) {
            Ok(()) => {
                return Ok(TrustLock {
                    path: path.to_path_buf(),
                    owner: candidate.1.clone(),
                });
            }
            Err(error) if is_contention(&error) && Instant::now() < deadline => {
                recover(path)?;
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(error) => return Err(error),
        }
    }
}

fn is_nonce(nonce: &str) -> bool {
    nonce.len() == 36
        && nonce
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b) || b == b'-')
}

fn is_contention(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        ErrorKind::AlreadyExists | ErrorKind::DirectoryNotEmpty
    ) || (cfg!(windows) && error.kind() == ErrorKind::PermissionDenied)
}

fn recover(path: &Path) -> io::Result<()> {
    let mut entries = match fs::read_dir(path) {
        Ok(entries) => entries,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if let Some(entry) = entries.next().transpose()? {
        if entries.next().transpose()?.is_some() {
            return Ok(());
        }
        let name = entry.file_name();
        let Some((pid, nonce)) = name.to_str().and_then(|name| name.split_once('-')) else {
            return Ok(());
        };
        let Ok(pid) = pid.parse::<i32>() else {
            return Ok(());
        };
        if pid <= 0 || !is_nonce(nonce) || !is_dead(pid) {
            return Ok(());
        }
        match fs::remove_file(entry.path()) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }

    drop(entries);

    // Deleting the observed marker selected by PID and nonce leaves the
    // directory empty. If a successor has since arrived, this rmdir fails.
    match fs::remove_dir(path) {
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::NotFound | ErrorKind::DirectoryNotEmpty | ErrorKind::AlreadyExists
            ) =>
        {
            Ok(())
        }
        result => result,
    }
}

#[cfg(unix)]
fn is_dead(pid: i32) -> bool {
    // SAFETY: Positive PID and signal zero query existence without signalling.
    unsafe {
        libc::kill(pid, 0) == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
    }
}

#[cfg(windows)]
fn is_dead(pid: i32) -> bool {
    use std::ffi::c_void;
    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    const ERROR_INVALID_PARAMETER: i32 = 87;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut c_void;
        fn CloseHandle(handle: *mut c_void) -> i32;
    }

    // SAFETY: OpenProcess only queries the process. A successful handle is
    // closed here without being used by any other code.
    unsafe {
        let handle: *mut c_void =
            OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid.unsigned_abs());
        if handle.is_null() {
            io::Error::last_os_error().raw_os_error() == Some(ERROR_INVALID_PARAMETER)
        } else {
            CloseHandle(handle);
            false
        }
    }
}

#[cfg(not(any(unix, windows)))]
fn is_dead(_pid: i32) -> bool {
    false
}
