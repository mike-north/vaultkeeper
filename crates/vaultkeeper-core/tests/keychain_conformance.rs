//! macOS conformance test for [`vaultkeeper_core::backend::KeychainBackend`]
//! against the *real* `security(1)` binary and a real Keychain, using an
//! ephemeral `create-keychain` so this test never touches the developer's or
//! CI runner's real login keychain (issue #290, AC5).
//!
//! # Why this lives here, not in `vaultkeeper-conformance`
//!
//! Mirrors `secret_tool_conformance.rs`'s rationale exactly: the
//! `vaultkeeper-conformance` crate's cases are CLI-level (fixed argv against
//! the `vaultkeeper` binary), and the native CLI does not yet support
//! selecting a backend at the command line — that wiring is a separate,
//! not-yet-landed epic item (`vaultkeeper-core` issue #273). Until that
//! lands there is no CLI invocation this test could shell out to that would
//! exercise `KeychainBackend` specifically, so this test instead drives the
//! backend directly, while still sharing assertion *data* with the CLI-level
//! conformance suite: the id/secret pair below is read straight out of
//! `vaultkeeper_conformance::all_cases()`'s `"store succeeds with valid
//! secret"` case rather than being duplicated by hand.
//!
//! # Ephemeral keychain isolation
//!
//! `KeychainBackend` (like the TS backend it ports) never passes `-k
//! <keychain>` to `security` — every command implicitly targets the current
//! *default* keychain for writes, and the current *search list* for reads
//! (`find-generic-password`, `delete-generic-password`, and critically
//! `dump-keychain`, which `list()` uses, walk every keychain on the search
//! list, not just the default one). To exercise the real backend without
//! observing — or polluting — whatever keychains a developer or CI runner
//! already has configured, this test:
//!
//! 1. Creates a throwaway keychain file in a temp directory with a random
//!    password (`security create-keychain`).
//! 2. Captures the current search list, then **replaces** it with just the
//!    ephemeral keychain (`security list-keychains -s <ephemeral>`) — not
//!    merely prepends it — so `dump-keychain`'s `list()` scan can only ever
//!    observe entries this test itself wrote, never a developer's or
//!    runner's real login-keychain entries. (Relying on `default-keychain
//!    -s` alone to also fix up the search list was tried and rejected: it
//!    was observed, empirically, to sometimes silently mutate the search
//!    list as a side effect and sometimes not, which is exactly the kind of
//!    OS/version-dependent behavior this isolation must not depend on.)
//! 3. Unlocks the ephemeral keychain and makes it the default
//!    (`unlock-keychain`, `default-keychain -s`) so unqualified `security`
//!    write commands (`add-generic-password`) resolve to it.
//! 4. Disables auto-lock for the duration of the test
//!    (`set-keychain-settings`) so a slow CI run doesn't hit a relock.
//! 5. Runs the full store/retrieve/exists/list/delete conformance flow.
//! 6. Restores the previous search list and default keychain, then deletes
//!    the ephemeral keychain file (`security delete-keychain`) — via an RAII
//!    guard so this cleanup runs even if an assertion above panics.
//!
//! # Gating
//!
//! Only meaningful on `target_os = "macos"` with `security` on PATH (true of
//! every macOS runner image). Everywhere else the test detects the missing
//! prerequisite and skips itself with a clear message, mirroring
//! `secret_tool_conformance.rs`'s Linux/D-Bus gate.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use vaultkeeper_core::backend::{
    ExecOptions, ExecOutput, HostPlatform, KeychainBackend, ListableBackend, Platform,
    SecretBackend,
};
use vaultkeeper_core::errors::VaultError;

/// Minimal real `HostPlatform` sufficient for `KeychainBackend`, which never
/// touches the filesystem. File methods are unreachable in practice — they
/// panic instead of silently doing the wrong thing if that assumption ever
/// changes.
struct RealMacHost {
    config_dir: PathBuf,
}

#[async_trait::async_trait]
impl HostPlatform for RealMacHost {
    async fn exec(
        &self,
        cmd: &str,
        args: &[&str],
        options: ExecOptions<'_>,
    ) -> Result<ExecOutput, VaultError> {
        let mut command = Command::new(cmd);
        command.args(args);
        command.stdin(if options.stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        });
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());

        let mut child = command
            .spawn()
            .map_err(|e| VaultError::Other(format!("Failed to spawn {cmd}: {e}")))?;

        if let Some(data) = options.stdin {
            use std::io::Write;
            if let Some(ref mut stdin) = child.stdin {
                stdin
                    .write_all(data)
                    .map_err(|e| VaultError::Other(format!("Failed to write stdin: {e}")))?;
            }
        }

        let output = child
            .wait_with_output()
            .map_err(|e| VaultError::Other(format!("Failed to wait for {cmd}: {e}")))?;

        Ok(ExecOutput {
            stdout: output.stdout,
            stderr: output.stderr,
            exit_code: output.status.code().unwrap_or(-1),
        })
    }

    async fn read_file(&self, _path: &Path) -> Result<Vec<u8>, VaultError> {
        unreachable!("KeychainBackend never touches the filesystem")
    }

    async fn write_file(
        &self,
        _path: &Path,
        _content: &[u8],
        _mode: u32,
    ) -> Result<(), VaultError> {
        unreachable!("KeychainBackend never touches the filesystem")
    }

    async fn file_exists(&self, _path: &Path) -> Result<bool, VaultError> {
        unreachable!("KeychainBackend never touches the filesystem")
    }

    async fn delete_file(&self, _path: &Path) -> Result<(), VaultError> {
        unreachable!("KeychainBackend never touches the filesystem")
    }

    async fn list_dir(&self, _path: &Path) -> Result<Vec<String>, VaultError> {
        unreachable!("KeychainBackend never touches the filesystem")
    }

    fn platform(&self) -> Platform {
        Platform::Darwin
    }

    fn config_dir(&self) -> &Path {
        &self.config_dir
    }
}

/// True only on macOS with `security` on PATH.
fn keychain_environment_available() -> bool {
    if !cfg!(target_os = "macos") {
        return false;
    }
    Command::new("security")
        .arg("list-keychains")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

/// Extract the `--name`/stdin fixture the CLI-level conformance suite
/// already asserts on, so this test's id/secret aren't a second,
/// hand-duplicated copy of that data.
fn shared_store_fixture() -> (String, String) {
    let case = vaultkeeper_conformance::all_cases()
        .into_iter()
        .find(|c| c.name == "store succeeds with valid secret")
        .expect("vaultkeeper-conformance must define 'store succeeds with valid secret'");

    let name_flag_pos = case
        .command
        .iter()
        .position(|arg| arg == "--name")
        .expect("case must pass --name");
    let name = case.command[name_flag_pos + 1].clone();
    let secret = case.stdin.expect("case must supply stdin secret");
    (name, secret)
}

/// Runs a `security` command with a fixed argv (no stdin). Panics only if
/// the process cannot be spawned; a non-zero exit is returned to the caller,
/// who decides whether it is fatal (setup asserts success; teardown is
/// best-effort). Used only for ephemeral-keychain setup/teardown, never for
/// anything touching the secret under test.
fn run_security(args: &[&str]) -> std::process::Output {
    Command::new("security")
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("failed to spawn `security {args:?}`: {e}"))
}

/// Like [`run_security`], but panics (with stderr) unless the command exits
/// zero — for setup reads whose output the harness depends on: proceeding
/// with an empty capture would silently skip session-state restoration in
/// `Drop`, leaving the runner's keychain configuration mutated.
fn run_security_ok(args: &[&str]) -> std::process::Output {
    let out = run_security(args);
    assert!(
        out.status.success(),
        "security {args:?} failed with exit {:?}: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

/// Parse `security list-keychains`/`security default-keychain` output —
/// one double-quoted path per line — into bare path strings.
fn parse_quoted_keychain_paths(stdout: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(stdout)
        .lines()
        .map(|line| line.trim().trim_matches('"').to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// RAII guard that creates an ephemeral keychain for the duration of the
/// test, replaces the search list with just that keychain (so `list()`'s
/// `dump-keychain` scan can never observe a pre-existing login-keychain
/// entry), and restores the prior search list + default keychain on drop —
/// so cleanup runs even if an assertion panics mid-test.
struct EphemeralKeychain {
    path: PathBuf,
    previous_search_list: Vec<String>,
    previous_default: Option<String>,
}

/// Distinguishes concurrently-running tests within the same test binary
/// process: `cargo test` runs each `#[tokio::test]` in this file on its own
/// thread of the same process by default, so `std::process::id()` alone is
/// not unique enough to keep two tests' ephemeral keychain files from
/// colliding on the same path.
static EPHEMERAL_KEYCHAIN_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

impl EphemeralKeychain {
    fn create() -> Self {
        let seq = EPHEMERAL_KEYCHAIN_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "vk-conformance-{}-{seq}.keychain-db",
            std::process::id()
        ));
        // Best-effort: clear out a stale keychain from a previous crashed run.
        let _ = std::fs::remove_file(&path);

        let previous_search_list =
            parse_quoted_keychain_paths(&run_security_ok(&["list-keychains"]).stdout);
        assert!(
            !previous_search_list.is_empty(),
            "list-keychains returned no paths — refusing to proceed, since Drop \
             could not restore the session's search list afterwards"
        );
        let previous_default =
            parse_quoted_keychain_paths(&run_security_ok(&["default-keychain"]).stdout)
                .into_iter()
                .next();

        let password = format!(
            "vk-conformance-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        );
        let path_str = path.to_str().expect("temp path must be valid UTF-8");

        let create = run_security(&["create-keychain", "-p", &password, path_str]);
        assert!(
            create.status.success(),
            "security create-keychain failed: {}",
            String::from_utf8_lossy(&create.stderr)
        );

        let unlock = run_security(&["unlock-keychain", "-p", &password, path_str]);
        assert!(
            unlock.status.success(),
            "security unlock-keychain failed: {}",
            String::from_utf8_lossy(&unlock.stderr)
        );

        // Disable auto-lock so a slow CI run can't relock the keychain
        // mid-test: `set-keychain-settings` with no `-t`/`-l` flags at all
        // sets no idle timeout and does not lock on sleep, which is exactly
        // the "never auto-lock" behavior wanted here — no args are actually
        // passed beyond the keychain path itself.
        let settings = run_security(&["set-keychain-settings", path_str]);
        assert!(
            settings.status.success(),
            "security set-keychain-settings failed: {}",
            String::from_utf8_lossy(&settings.stderr)
        );

        // Replace (not prepend) the search list with just the ephemeral
        // keychain. This is what actually isolates `list()`'s
        // `dump-keychain` scan from a developer's or runner's real
        // login-keychain entries — `dump-keychain` (no `-k`) walks every
        // keychain on the search list, not just the default one.
        let set_search_list = run_security(&["list-keychains", "-s", path_str]);
        assert!(
            set_search_list.status.success(),
            "security list-keychains -s failed: {}",
            String::from_utf8_lossy(&set_search_list.stderr)
        );

        let set_default = run_security(&["default-keychain", "-s", path_str]);
        assert!(
            set_default.status.success(),
            "security default-keychain -s failed: {}",
            String::from_utf8_lossy(&set_default.stderr)
        );

        Self {
            path,
            previous_search_list,
            previous_default,
        }
    }
}

impl Drop for EphemeralKeychain {
    fn drop(&mut self) {
        if !self.previous_search_list.is_empty() {
            let mut args = vec!["list-keychains", "-s"];
            args.extend(self.previous_search_list.iter().map(String::as_str));
            let _ = run_security(&args);
        }
        if let Some(previous) = &self.previous_default {
            let _ = run_security(&["default-keychain", "-s", previous]);
        }
        let path_str = self.path.to_string_lossy().to_string();
        let _ = run_security(&["delete-keychain", &path_str]);
        let _ = std::fs::remove_file(&self.path);
    }
}

// `EphemeralKeychain::create`/`Drop` mutate *global*, session-wide state
// (`security list-keychains -s` / `security default-keychain -s`), not
// anything scoped to the ephemeral keychain file itself. Two tests in this
// file running concurrently (the default for `#[tokio::test]`s in the same
// binary) would race on that shared state and could restore the wrong
// "previous" search list/default keychain on drop — serialize them onto one
// real OS thread instead.
#[tokio::test]
#[serial_test::serial(keychain_session_state)]
async fn keychain_backend_conformance_against_real_security_binary() {
    if !keychain_environment_available() {
        eprintln!(
            "skipping keychain_backend_conformance_against_real_security_binary: \
             requires target_os=macos and `security` on PATH. This is \
             expected on non-macOS development machines and CI runners \
             (issue #290 AC5)."
        );
        return;
    }

    let ephemeral = EphemeralKeychain::create();

    let host = std::sync::Arc::new(RealMacHost {
        config_dir: std::env::temp_dir(),
    });
    let backend = KeychainBackend::new(host);
    let (name, secret) = shared_store_fixture();
    // Namespace the id so repeated runs against a reused keychain path don't
    // collide with a leftover entry from a previous run.
    let name = format!("{name}-{}", std::process::id());

    assert!(
        backend.is_available().await,
        "security must be available and the ephemeral keychain reachable"
    );

    backend
        .store(&name, &secret)
        .await
        .expect("store must succeed against a real Keychain");

    assert!(
        backend.exists(&name).await.unwrap(),
        "exists must be true immediately after store"
    );

    let retrieved = backend
        .retrieve(&name)
        .await
        .expect("retrieve must succeed for a just-stored entry");
    assert_eq!(
        retrieved, secret,
        "retrieved secret must match the stored value byte-for-byte"
    );

    let listed = backend.list().await.expect("list must succeed");
    // Not just `contains` — the search-list replacement in
    // `EphemeralKeychain::create` is what actually isolates this scan from
    // a developer's or runner's real login-keychain entries, so assert the
    // *only* thing visible is what this test itself stored.
    assert_eq!(
        listed,
        vec![name.clone()],
        "list must observe exactly this test's own entry, nothing from a \
         pre-existing login keychain: {listed:?}"
    );

    backend
        .delete(&name)
        .await
        .expect("delete must succeed for an existing entry");

    assert!(
        !backend.exists(&name).await.unwrap(),
        "exists must be false immediately after delete"
    );

    let err = backend
        .retrieve(&name)
        .await
        .expect_err("retrieve of a deleted entry must fail");
    assert!(
        matches!(err, VaultError::SecretNotFound { .. }),
        "expected SecretNotFound after delete, got {err:?}"
    );

    let delete_err = backend
        .delete(&name)
        .await
        .expect_err("deleting an already-deleted entry must fail");
    assert!(
        matches!(delete_err, VaultError::SecretNotFound { .. }),
        "expected SecretNotFound deleting a missing entry, got {delete_err:?}"
    );

    drop(ephemeral);
}

/// Conformance-level regression for the store/list asymmetry (issue #304
/// review): `store()` supports an id with an embedded double quote (escaped
/// for `security -i`'s tokenizer), but real `security dump-keychain`'s
/// plain-quoted display form embeds the quote raw and unescaped, so `list()`
/// must not truncate the id at the first embedded quote. Runs against the
/// real `security` binary and a real (ephemeral) keychain, not just the
/// in-memory `TestHost` in `keychain.rs`'s unit tests.
#[tokio::test]
#[serial_test::serial(keychain_session_state)]
async fn keychain_backend_list_round_trips_a_quoted_id_against_real_security_binary() {
    if !keychain_environment_available() {
        eprintln!(
            "skipping keychain_backend_list_round_trips_a_quoted_id_against_real_security_binary: \
             requires target_os=macos and `security` on PATH."
        );
        return;
    }

    let ephemeral = EphemeralKeychain::create();

    let host = std::sync::Arc::new(RealMacHost {
        config_dir: std::env::temp_dir(),
    });
    let backend = KeychainBackend::new(host);
    let id = format!("has \"quotes\" inside-{}", std::process::id());

    backend
        .store(&id, "quoted-id-secret")
        .await
        .expect("store must succeed for an id with an embedded double quote");

    let listed = backend.list().await.expect("list must succeed");
    assert_eq!(
        listed,
        vec![id.clone()],
        "list() must recover the full id, not truncate at the first embedded quote: {listed:?}"
    );

    assert_eq!(
        backend.retrieve(&id).await.unwrap(),
        "quoted-id-secret",
        "retrieve must still work for the same quoted id"
    );

    backend
        .delete(&id)
        .await
        .expect("delete must succeed for the quoted-id entry");

    drop(ephemeral);
}
