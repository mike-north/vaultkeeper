//! macOS Keychain backend, driven via the `security(1)` CLI.
//!
//! Ports the TypeScript `KeychainBackend`
//! (`packages/vaultkeeper/src/backend/keychain-backend.ts`) into
//! `vaultkeeper-core`, unchanged in wire behavior: same account/service
//! naming (`vaultkeeper` account, `vaultkeeper:<id>` service), same
//! base64-encoded generic-password storage. Entries written by either
//! implementation are mutually readable because the naming scheme below is
//! byte-for-byte identical to the TS backend's.
//!
//! # The `store` argv-leak problem, and its resolution (issue #290)
//!
//! The TS backend's `store()` passes the base64-encoded secret as
//! `security add-generic-password ... -w <encoded>` — a plain argv command.
//! That puts the secret in this process's argv, visible to `ps`/Activity
//! Monitor for the (brief) lifetime of the child process. `security`'s
//! direct `-w` flag has no stdin channel: `-w <value>` always puts `<value>`
//! in argv, and `-w` with no value falls back to an interactive `getpass()`
//! TTY prompt that ignores piped stdin (verified empirically: piping a
//! command stream at a bare trailing `-w` produces `password data for new
//! item: retype password for new item:` prompt text and does not read the
//! intended value).
//!
//! **Resolution:** `security -i` ("interactive mode") reads *multiple*
//! commands from stdin, one per line, until EOF — see `man security`. Run as
//! `security -i` with no other argv, the OS-visible argv is just `security
//! -i`; the entire `add-generic-password ... -w <value>` command instead
//! rides the stdin command stream, never touching argv. This was verified
//! directly before implementation:
//!
//! ```text
//! $ printf 'add-generic-password -a t -s vk-spike -w dGVzdA==\n' | security -i
//! $ security find-generic-password -a t -s vk-spike -w
//! dGVzdA==
//! ```
//!
//! The value came back byte-for-byte, confirming `-w <value>` is parsed off
//! the `-i` stdin stream rather than diverted to the TTY prompt. `store()`
//! stays a plain [`HostPlatform::exec`] call (which already carries stdin) —
//! no Security.framework FFI, no host split, no wasm-portability loss.
//!
//! base64-encoding the secret before it enters the stdin script is
//! *load-bearing* and is kept unchanged from the TS backend: the base64 alphabet
//! (`A-Za-z0-9+/=`) contains no character `security -i`'s command tokenizer
//! treats specially, so `-w <base64>` is always exactly one clean token
//! regardless of what bytes the underlying secret contains.
//!
//! ## Scope: only `store` uses the command stream
//!
//! `retrieve` (`find-generic-password -w`, secret on stdout only),
//! `delete`/`exists` (no secret in argv at all), and `list`
//! (`dump-keychain` + parse) are all argv-safe as plain `security <args...>`
//! exec calls — porting them 1:1 from the TS backend needs no `-i` handling.
//!
//! ## Quoting the account/service tokens in the `-i` stdin script
//!
//! Unlike a plain argv call, the `-i` stdin stream is *tokenized by
//! `security` itself* (its own quoting rules, not the shell's). The account
//! (`vaultkeeper`, a fixed constant) and service (`vaultkeeper:<id>`, where
//! `<id>` is caller-supplied) are embedded as double-quoted tokens with `\`
//! and `"` backslash-escaped, verified empirically to round-trip service
//! names containing spaces, embedded double quotes, and embedded backslashes
//! correctly through `security -i`. An embedded newline (`\n` or `\r`) in
//! `<id>` cannot be escaped by this scheme — it would prematurely terminate
//! the current `-i` command line and let an attacker-controlled `id` inject
//! arbitrary follow-on `security -i` subcommands. `id` values (and a NUL
//! byte, which no `security` command can represent at all) are therefore
//! **enforced** to be single-line: every public method on this backend
//! rejects such an `id` with a typed [`VaultError`] before issuing any
//! subprocess call at all.
//!
//! ## Coordination with #270
//!
//! The TS `KeychainBackend`'s argv leak is also tracked as standalone defect
//! #270. This Rust-core port supersedes it with the `security -i` design
//! described above; #270 is left open to apply the equivalent fix to the TS
//! implementation, which this PR does not touch.
//!
//! ## Known edge cases
//!
//! - **Non-atomic overwrite window.** `store()`'s `-i` script is
//!   `delete-generic-password` immediately followed by `add-generic-password`
//!   *within the same `security -i` process*, but `security` still executes
//!   them as two separate Keychain operations, not one transaction. If the
//!   delete succeeds but the add then fails (e.g. the keychain is locked or
//!   disk-full partway through), the old secret is already gone and the new
//!   one was never written — the entry is left missing, not merely stale.
//! - **Cross-process store/store race.** Two processes calling `store()` for
//!   the same `id` at the same time can both pass their own delete before
//!   either add runs, then both add succeed (each against an
//!   already-cleared slot) or one add fails with "item already exists" if it
//!   loses the race to the other's add — `security` provides no
//!   compare-and-swap primitive this backend could use to serialize the two
//!   Keychain writes.

use crate::backend::types::{ExecOptions, HostPlatform, ListableBackend, Platform, SecretBackend};
use crate::errors::VaultError;
use base64ct::{Base64, Encoding};
use std::sync::Arc;

/// Keychain account used for every vaultkeeper-managed entry. Must match the
/// TS backend's `ACCOUNT` exactly.
const ACCOUNT: &str = "vaultkeeper";

/// Service name prefix applied to every vaultkeeper-managed entry. Must
/// match the TS backend's `SERVICE_PREFIX` exactly.
const SERVICE_PREFIX: &str = "vaultkeeper:";

/// macOS Keychain secret backend, driven entirely through `security(1)`
/// subprocess calls via [`HostPlatform::exec`].
///
/// Only meaningfully available on Darwin (macOS) with the `security` CLI on
/// PATH.
pub struct KeychainBackend {
    host: Arc<dyn HostPlatform>,
}

impl KeychainBackend {
    /// Create a new `KeychainBackend` using the given host for subprocess
    /// orchestration.
    pub fn new(host: Arc<dyn HostPlatform>) -> Self {
        Self { host }
    }

    fn service_name(id: &str) -> String {
        format!("{SERVICE_PREFIX}{id}")
    }

    /// The `SecCopyErrorMessageString` text Apple's Security framework emits
    /// for `errSecInteractionNotAllowed` (-25308) — the standard OSStatus a
    /// locked keychain returns when a command needs to decrypt/read item
    /// data (or otherwise requires a keychain-unlock prompt) and no
    /// interactive session is available to show one, e.g. a headless CI
    /// runner with no login session. `security(1)` surfaces this verbatim on
    /// stderr. Matched case-insensitively as a substring, not tied to a
    /// specific exit code: on a real macOS login session *with* GUI access
    /// (verified empirically on this development machine), a locked-
    /// keychain `find-generic-password -w` instead blocks indefinitely on an
    /// interactive Security Agent unlock prompt rather than failing fast, so
    /// no single fast-failing exit code could be captured live here — the
    /// documented Apple error text is the one part of this signature that's
    /// stable regardless of which of those two behaviors a given runner
    /// exhibits.
    const LOCKED_KEYCHAIN_STDERR_SIGNATURE: &str = "user interaction is not allowed";

    /// True if `stderr` carries the [`Self::LOCKED_KEYCHAIN_STDERR_SIGNATURE`]
    /// for a locked keychain that can't be read non-interactively.
    fn is_locked_keychain_error(stderr: &[u8]) -> bool {
        String::from_utf8_lossy(stderr)
            .to_lowercase()
            .contains(Self::LOCKED_KEYCHAIN_STDERR_SIGNATURE)
    }

    /// Reject an `id` containing a newline (`\n`/`\r`) or NUL byte before
    /// any `security` subprocess is issued.
    ///
    /// `store()` embeds `id` inside a `security -i` stdin command stream
    /// that `security` itself tokenizes line-by-line; a newline in `id`
    /// cannot be escaped there and would terminate the current command
    /// line, letting the rest of `id` be interpreted as one or more
    /// additional `security -i` subcommands (see module docs). `retrieve`,
    /// `delete`, and `exists` don't use the `-i` stream, but reject the same
    /// ids for consistency: an id with an embedded newline could never have
    /// been produced by a successful `store()` on this backend, so refusing
    /// it uniformly avoids surprising per-method behavior.
    fn reject_multiline_id(id: &str) -> Result<(), VaultError> {
        if id.contains('\n') || id.contains('\r') || id.contains('\0') {
            return Err(VaultError::Other(format!(
                "macOS Keychain secret id must not contain a newline, carriage return, or NUL byte: {id:?}"
            )));
        }
        Ok(())
    }

    /// Quote `value` as a single token for `security -i`'s stdin command
    /// tokenizer: wrap in double quotes, backslash-escaping any embedded `\`
    /// or `"` — verified empirically (see module docs) to round-trip
    /// spaces, embedded double quotes, and embedded backslashes.
    fn quote_for_interactive_stream(value: &str) -> String {
        let mut quoted = String::with_capacity(value.len() + 2);
        quoted.push('"');
        for c in value.chars() {
            if c == '\\' || c == '"' {
                quoted.push('\\');
            }
            quoted.push(c);
        }
        quoted.push('"');
        quoted
    }

    /// Parse a `security dump-keychain` attribute line for the
    /// `0x00000007 <blob>=...` (service name) attribute, returning the raw
    /// UTF-8 string value regardless of which of `security`'s two display
    /// forms was used:
    ///
    /// - Plain quoted form (fully printable ASCII, no backslash): `="<value>"`.
    /// - Hex + octal-escaped display form (any byte outside printable ASCII,
    ///   or containing a backslash): `=0x<HEX>  "<octal-escaped display>"` —
    ///   the hex digits are the authoritative raw bytes; the quoted text
    ///   afterwards is only a lossy human-readable rendering, so this parses
    ///   the hex form when present rather than the ambiguous quoted display.
    ///
    /// The plain quoted form does **not** escape a `"` embedded in the
    /// value — verified empirically against the real `security` binary: an
    /// id of `ends with quote"` dumps as `="vaultkeeper:ends with quote""`,
    /// i.e. the line simply ends with two consecutive `"` (the embedded one,
    /// then the true closing delimiter), with no distinguishing escape
    /// between them. Locating the *first* embedded `"` (as if it always
    /// closed the value) truncates the id at that point and silently drops
    /// everything after it — this parses the *last* `"` on the line as the
    /// closing delimiter instead, which is unambiguous because `security`
    /// never emits anything after the closing quote on a `<blob>` line
    /// (verified empirically: no trailing whitespace or content follows).
    fn parse_service_attribute_line(line: &str) -> Option<String> {
        let rest = line.trim_start().strip_prefix("0x00000007 <blob>=")?;
        if let Some(hex) = rest.strip_prefix("0x") {
            let hex_digits: String = hex.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
            if hex_digits.is_empty() || !hex_digits.len().is_multiple_of(2) {
                return None;
            }
            let mut bytes = Vec::with_capacity(hex_digits.len() / 2);
            let hex_bytes = hex_digits.as_bytes();
            for chunk in hex_bytes.chunks(2) {
                let byte_str = std::str::from_utf8(chunk).ok()?;
                bytes.push(u8::from_str_radix(byte_str, 16).ok()?);
            }
            String::from_utf8(bytes).ok()
        } else {
            let quoted = rest.strip_prefix('"')?;
            let end = quoted.rfind('"')?;
            Some(quoted[..end].to_string())
        }
    }

    /// Parse every `vaultkeeper:<id>` service name out of `security
    /// dump-keychain` output, returning the bare `<id>` portion — mirrors
    /// the TS backend's `/0x00000007 <blob>="vaultkeeper:([^"]+)"/g` regex,
    /// generalized to also cover `security`'s hex-escaped display form for
    /// non-printable-ASCII names (see [`Self::parse_service_attribute_line`]).
    fn parse_dump_ids(stdout: &str) -> Vec<String> {
        stdout
            .lines()
            .filter_map(Self::parse_service_attribute_line)
            .filter_map(|service| service.strip_prefix(SERVICE_PREFIX).map(str::to_string))
            .collect()
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl SecretBackend for KeychainBackend {
    fn backend_type(&self) -> &str {
        "keychain"
    }

    fn display_name(&self) -> &str {
        "macOS Keychain"
    }

    async fn is_available(&self) -> bool {
        if self.host.platform() != Platform::Darwin {
            return false;
        }
        // `security version` is not a real subcommand (verified empirically
        // to always fail with "unknown command"), unlike the TS backend's
        // probe which relies on it. `list-keychains` is a real, read-only,
        // side-effect-free command that both confirms `security` is on PATH
        // and that it can actually talk to the keychain subsystem.
        match self
            .host
            .exec("security", &["list-keychains"], ExecOptions::default())
            .await
        {
            Ok(output) => output.exit_code == 0,
            Err(_) => false,
        }
    }

    async fn store(&self, id: &str, secret: &str) -> Result<(), VaultError> {
        Self::reject_multiline_id(id)?;
        let service = Self::service_name(id);
        let account_token = Self::quote_for_interactive_stream(ACCOUNT);
        let service_token = Self::quote_for_interactive_stream(&service);
        let encoded = Base64::encode_string(secret.as_bytes());

        // Single `security -i` process for the whole store operation (both
        // the pre-delete of any existing entry and the fresh add), so the
        // secret's only appearance anywhere is on this one process's stdin.
        // `security -i`'s overall exit code reflects the *last* command run
        // in the stream, so a failing pre-delete (no prior entry) followed
        // by a successful add still yields exit code 0 — verified
        // empirically (see module docs).
        // `encoded` is quoted so an empty secret still yields a value token
        // (`-w ""`): a bare trailing `-w` would flip `security` into its
        // interactive getpass prompt and hang a non-interactive caller.
        // Base64 output never contains `"`/`\`/newline, so plain quoting is
        // exact (no escaping needed) — enforced by the debug_assert below.
        debug_assert!(
            !encoded.contains(['"', '\\', '\n', '\r']),
            "base64 output must be quote-safe"
        );
        let script = format!(
            "delete-generic-password -a {account_token} -s {service_token}\n\
             add-generic-password -a {account_token} -s {service_token} -w \"{encoded}\"\n"
        );

        let output = self
            .host
            .exec(
                "security",
                &["-i"],
                ExecOptions {
                    stdin: Some(script.as_bytes()),
                    ..Default::default()
                },
            )
            .await?;
        if output.exit_code != 0 {
            // Deliberately does NOT embed `output.stderr` here, unlike every
            // other error path in this file. Every other `security`
            // subprocess in this backend is invoked with an argv-only
            // command (no stdin secret involved), so its stderr is safe to
            // surface verbatim for diagnostics. This is the one process
            // whose stdin carries the secret (in `encoded`, base64-encoded)
            // — verified empirically that real `security -i`'s stderr never
            // echoes the command line or `-w` value back (only a status
            // line like `add-generic-password: returned -25299`), but that
            // is an unenforced behavioral property of a third-party binary,
            // not a contract this backend can rely on. Omitting stderr here
            // entirely removes any path for a future `security` version (or
            // an unanticipated error mode) to leak the secret or its base64
            // encoding into a `VaultError` message that might be logged.
            // Locked-keychain detection mirrors retrieve/delete/exists —
            // still without embedding stderr (the signature check reads it,
            // the error message never includes it).
            if Self::is_locked_keychain_error(&output.stderr) {
                return Err(VaultError::BackendLocked {
                    message: format!(
                        "macOS Keychain is locked and cannot be written non-interactively for {id}"
                    ),
                    interactive: true,
                });
            }
            return Err(VaultError::Exec {
                message: format!(
                    "security add-generic-password failed with exit code {}",
                    output.exit_code
                ),
                command: "security".to_string(),
            });
        }
        Ok(())
    }

    async fn retrieve(&self, id: &str) -> Result<String, VaultError> {
        Self::reject_multiline_id(id)?;
        let service = Self::service_name(id);
        let output = self
            .host
            .exec(
                "security",
                &[
                    "find-generic-password",
                    "-a",
                    ACCOUNT,
                    "-s",
                    service.as_str(),
                    "-w",
                ],
                ExecOptions::default(),
            )
            .await?;
        if output.exit_code != 0 {
            if Self::is_locked_keychain_error(&output.stderr) {
                return Err(VaultError::BackendLocked {
                    message: format!(
                        "macOS Keychain is locked and cannot be read non-interactively for {id}"
                    ),
                    interactive: true,
                });
            }
            return Err(VaultError::SecretNotFound {
                message: format!("Secret not found in macOS Keychain: {id}"),
            });
        }
        let encoded = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let decoded = Base64::decode_vec(&encoded).map_err(|e| {
            VaultError::Other(format!(
                "macOS Keychain returned malformed base64 for {id}: {e}"
            ))
        })?;
        String::from_utf8(decoded).map_err(|e| {
            VaultError::Other(format!(
                "macOS Keychain entry for {id} decoded to invalid UTF-8: {e}"
            ))
        })
    }

    async fn delete(&self, id: &str) -> Result<(), VaultError> {
        Self::reject_multiline_id(id)?;
        let service = Self::service_name(id);
        let output = self
            .host
            .exec(
                "security",
                &[
                    "delete-generic-password",
                    "-a",
                    ACCOUNT,
                    "-s",
                    service.as_str(),
                ],
                ExecOptions::default(),
            )
            .await?;
        if output.exit_code != 0 {
            if Self::is_locked_keychain_error(&output.stderr) {
                return Err(VaultError::BackendLocked {
                    message: format!(
                        "macOS Keychain is locked and cannot be modified non-interactively for {id}"
                    ),
                    interactive: true,
                });
            }
            return Err(VaultError::SecretNotFound {
                message: format!("Secret not found in macOS Keychain: {id}"),
            });
        }
        Ok(())
    }

    async fn exists(&self, id: &str) -> Result<bool, VaultError> {
        Self::reject_multiline_id(id)?;
        let service = Self::service_name(id);
        let output = self
            .host
            .exec(
                "security",
                &[
                    "find-generic-password",
                    "-a",
                    ACCOUNT,
                    "-s",
                    service.as_str(),
                ],
                ExecOptions::default(),
            )
            .await?;
        if output.exit_code != 0 && Self::is_locked_keychain_error(&output.stderr) {
            return Err(VaultError::BackendLocked {
                message: format!(
                    "macOS Keychain is locked and cannot be queried non-interactively for {id}"
                ),
                interactive: true,
            });
        }
        Ok(output.exit_code == 0)
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl ListableBackend for KeychainBackend {
    async fn list(&self) -> Result<Vec<String>, VaultError> {
        let output = self
            .host
            .exec("security", &["dump-keychain"], ExecOptions::default())
            .await?;
        if output.exit_code != 0 {
            return Ok(Vec::new());
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(Self::parse_dump_ids(&stdout))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::ExecOutput;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    /// Records every `exec` invocation (command, args, stdin) so tests can
    /// assert on exactly what was shelled out — in particular, the
    /// argv-sentinel assertion for AC1.
    #[derive(Debug, Clone)]
    struct RecordedExec {
        cmd: String,
        args: Vec<String>,
        stdin: Option<Vec<u8>>,
    }

    /// Test double for `HostPlatform` that fakes a macOS Keychain in memory,
    /// keyed by service name, and records every subprocess invocation for
    /// argv inspection. Understands the `security -i` stdin command stream
    /// well enough to execute `delete-generic-password`/`add-generic-password`
    /// lines against its in-memory store, mirroring the real tool's
    /// behavior verified empirically before implementation.
    struct TestHost {
        config_dir: PathBuf,
        /// service -> secret (raw bytes as returned by `-w`, i.e. base64 text)
        entries: Mutex<std::collections::HashMap<String, String>>,
        calls: Mutex<Vec<RecordedExec>>,
        list_keychains_unavailable: bool,
        platform: Platform,
    }

    impl TestHost {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                config_dir: PathBuf::from("/test/config"),
                entries: Mutex::new(std::collections::HashMap::new()),
                calls: Mutex::new(Vec::new()),
                list_keychains_unavailable: false,
                platform: Platform::Darwin,
            })
        }

        /// Minimal re-implementation of `security -i`'s per-line tokenizer,
        /// just enough to parse the two command shapes this backend ever
        /// sends: `delete-generic-password -a <tok> -s <tok>` and
        /// `add-generic-password -a <tok> -s <tok> -w <value>`, where `<tok>`
        /// may be a double-quoted, backslash-escaped token.
        fn tokenize(line: &str) -> Vec<String> {
            let mut tokens = Vec::new();
            let mut chars = line.chars().peekable();
            while let Some(&c) = chars.peek() {
                if c.is_whitespace() {
                    chars.next();
                    continue;
                }
                if c == '"' {
                    chars.next();
                    let mut token = String::new();
                    while let Some(c) = chars.next() {
                        if c == '\\' {
                            if let Some(escaped) = chars.next() {
                                token.push(escaped);
                            }
                        } else if c == '"' {
                            break;
                        } else {
                            token.push(c);
                        }
                    }
                    tokens.push(token);
                } else {
                    let mut token = String::new();
                    while let Some(&c) = chars.peek() {
                        if c.is_whitespace() {
                            break;
                        }
                        token.push(c);
                        chars.next();
                    }
                    tokens.push(token);
                }
            }
            tokens
        }

        fn run_interactive_script(&self, script: &str) -> ExecOutput {
            let mut last_exit_code = 0;
            let mut stderr = Vec::new();
            for line in script.lines() {
                if line.trim().is_empty() {
                    continue;
                }
                let tokens = Self::tokenize(line);
                match tokens.first().map(String::as_str) {
                    Some("delete-generic-password") => {
                        let service = tokens.get(4).expect("service token").clone();
                        let removed = self.entries.lock().unwrap().remove(&service).is_some();
                        last_exit_code = if removed { 0 } else { 45 };
                        if !removed {
                            stderr.extend_from_slice(b"item not found\n");
                        }
                    }
                    Some("add-generic-password") => {
                        let service = tokens.get(4).expect("service token").clone();
                        let value = tokens.get(6).expect("-w value token").clone();
                        let mut entries = self.entries.lock().unwrap();
                        if let std::collections::hash_map::Entry::Vacant(e) = entries.entry(service)
                        {
                            e.insert(value);
                            last_exit_code = 0;
                        } else {
                            last_exit_code = 45;
                            stderr.extend_from_slice(b"item already exists\n");
                        }
                    }
                    other => panic!("unexpected -i command in test: {other:?}"),
                }
            }
            ExecOutput {
                stdout: Vec::new(),
                stderr,
                exit_code: last_exit_code,
            }
        }
    }

    #[async_trait::async_trait]
    impl HostPlatform for TestHost {
        async fn exec(
            &self,
            cmd: &str,
            args: &[&str],
            options: ExecOptions<'_>,
        ) -> Result<ExecOutput, VaultError> {
            self.calls.lock().unwrap().push(RecordedExec {
                cmd: cmd.to_string(),
                args: args.iter().map(|s| s.to_string()).collect(),
                stdin: options.stdin.map(|s| s.to_vec()),
            });

            match args.first().copied() {
                Some("list-keychains") => {
                    if self.list_keychains_unavailable {
                        return Ok(ExecOutput {
                            stdout: Vec::new(),
                            stderr: b"command not found".to_vec(),
                            exit_code: 127,
                        });
                    }
                    Ok(ExecOutput {
                        stdout: b"\"/test/login.keychain-db\"\n".to_vec(),
                        stderr: Vec::new(),
                        exit_code: 0,
                    })
                }
                Some("-i") => {
                    let script = options
                        .stdin
                        .map(|b| String::from_utf8_lossy(b).to_string())
                        .unwrap_or_default();
                    Ok(self.run_interactive_script(&script))
                }
                Some("find-generic-password") => {
                    let service = args.get(4).expect("service arg").to_string();
                    let wants_value = args.contains(&"-w");
                    match self.entries.lock().unwrap().get(&service) {
                        Some(value) => Ok(ExecOutput {
                            stdout: if wants_value {
                                format!("{value}\n").into_bytes()
                            } else {
                                Vec::new()
                            },
                            stderr: Vec::new(),
                            exit_code: 0,
                        }),
                        None => Ok(ExecOutput {
                            stdout: Vec::new(),
                            stderr: b"The specified item could not be found in the keychain."
                                .to_vec(),
                            exit_code: 44,
                        }),
                    }
                }
                Some("delete-generic-password") => {
                    let service = args.get(4).expect("service arg").to_string();
                    let removed = self.entries.lock().unwrap().remove(&service).is_some();
                    Ok(ExecOutput {
                        stdout: Vec::new(),
                        stderr: if removed {
                            Vec::new()
                        } else {
                            b"The specified item could not be found in the keychain.".to_vec()
                        },
                        exit_code: if removed { 0 } else { 44 },
                    })
                }
                Some("dump-keychain") => {
                    let entries = self.entries.lock().unwrap();
                    let mut stdout = String::new();
                    for service in entries.keys() {
                        let is_plain_ascii = service
                            .bytes()
                            .all(|b| (0x20..0x7f).contains(&b) && b != b'\\');
                        stdout.push_str("attributes:\n");
                        if is_plain_ascii {
                            stdout.push_str(&format!("    0x00000007 <blob>=\"{service}\"\n"));
                        } else {
                            let hex: String = service.bytes().map(|b| format!("{b:02X}")).collect();
                            stdout.push_str(&format!(
                                "    0x00000007 <blob>=0x{hex}  \"{service}\"\n"
                            ));
                        }
                    }
                    Ok(ExecOutput {
                        stdout: stdout.into_bytes(),
                        stderr: Vec::new(),
                        exit_code: 0,
                    })
                }
                other => panic!("unexpected security invocation: {other:?}"),
            }
        }
        async fn read_file(&self, _path: &Path) -> Result<Vec<u8>, VaultError> {
            panic!("KeychainBackend must not touch the filesystem")
        }
        async fn write_file(
            &self,
            _path: &Path,
            _content: &[u8],
            _mode: u32,
        ) -> Result<(), VaultError> {
            panic!("KeychainBackend must not touch the filesystem")
        }
        async fn file_exists(&self, _path: &Path) -> Result<bool, VaultError> {
            panic!("KeychainBackend must not touch the filesystem")
        }
        async fn delete_file(&self, _path: &Path) -> Result<(), VaultError> {
            panic!("KeychainBackend must not touch the filesystem")
        }
        async fn list_dir(&self, _path: &Path) -> Result<Vec<String>, VaultError> {
            panic!("KeychainBackend must not touch the filesystem")
        }
        fn platform(&self) -> Platform {
            self.platform
        }
        fn config_dir(&self) -> &Path {
            &self.config_dir
        }
    }

    // ── AC4 (naming parity): account/service scheme matches the TS backend ─

    #[test]
    fn account_matches_ts_backend() {
        // packages/vaultkeeper/src/backend/keychain-backend.ts: ACCOUNT
        assert_eq!(ACCOUNT, "vaultkeeper");
    }

    #[test]
    fn service_prefix_matches_ts_backend() {
        // packages/vaultkeeper/src/backend/keychain-backend.ts: SERVICE_PREFIX
        assert_eq!(SERVICE_PREFIX, "vaultkeeper:");
    }

    // ── AC1: store is argv-safe — the secret only ever travels on stdin,
    // as a single `security -i` process ─────────────────────────────────

    #[tokio::test]
    async fn store_issues_a_single_security_interactive_process() {
        let host = TestHost::new();
        let backend = KeychainBackend::new(host.clone());
        backend.store("my-secret", "secret-value").await.unwrap();

        let calls = host.calls.lock().unwrap();
        assert_eq!(calls.len(), 1, "store should issue exactly one exec call");
        assert_eq!(calls[0].cmd, "security");
        assert_eq!(calls[0].args, vec!["-i"]);
    }

    #[tokio::test]
    async fn store_overwrites_an_existing_entry_via_the_pre_delete_line() {
        // Regression coverage for the load-bearing `delete-generic-password`
        // line that precedes `add-generic-password` in store()'s -i script:
        // without it, a second store() for the same id would fail with the
        // real `security`'s "item already exists" error (verified
        // empirically — see module docs), since add-generic-password alone
        // never overwrites. TestHost's `run_interactive_script` mirrors
        // that duplicate-add failure, so this test genuinely fails if the
        // pre-delete line is removed.
        let host = TestHost::new();
        let backend = KeychainBackend::new(host.clone());

        backend.store("upsert-id", "first-value").await.unwrap();
        assert_eq!(backend.retrieve("upsert-id").await.unwrap(), "first-value");

        backend
            .store("upsert-id", "second-value")
            .await
            .expect("storing the same id again must succeed by overwriting, not erroring");
        assert_eq!(
            backend.retrieve("upsert-id").await.unwrap(),
            "second-value",
            "the second store must have replaced the first value"
        );
    }

    #[tokio::test]
    async fn store_passes_secret_and_its_base64_encoding_on_stdin_not_argv() {
        let host = TestHost::new();
        let backend = KeychainBackend::new(host.clone());
        const SENTINEL: &str = "argv-sentinel-should-never-appear-in-args";
        backend.store("sentinel-id", SENTINEL).await.unwrap();

        let encoded = Base64::encode_string(SENTINEL.as_bytes());
        let calls = host.calls.lock().unwrap();
        for call in calls.iter() {
            assert!(
                call.args.iter().all(|a| !a.contains(SENTINEL)),
                "the secret must never appear in child process argv: {:?}",
                call.args
            );
            assert!(
                call.args.iter().all(|a| !a.contains(&encoded)),
                "the base64-encoded secret must never appear in child process argv: {:?}",
                call.args
            );
        }
        let stdin = calls[0]
            .stdin
            .as_ref()
            .expect("store's exec call must carry stdin");
        let script = String::from_utf8_lossy(stdin);
        assert!(
            script.contains(&encoded),
            "the base64-encoded secret must be delivered on stdin: {script:?}"
        );
    }

    #[tokio::test]
    async fn store_argv_sentinel_survives_full_round_trip() {
        // Broader regression: run store -> retrieve -> exists -> delete and
        // assert the sentinel never leaked into argv at any step, not just
        // store.
        let host = TestHost::new();
        let backend = KeychainBackend::new(host.clone());
        const SENTINEL: &str = "super-secret-value-42";

        backend.store("rt-id", SENTINEL).await.unwrap();
        let retrieved = backend.retrieve("rt-id").await.unwrap();
        assert_eq!(retrieved, SENTINEL);
        assert!(backend.exists("rt-id").await.unwrap());
        backend.delete("rt-id").await.unwrap();

        let encoded = Base64::encode_string(SENTINEL.as_bytes());
        let calls = host.calls.lock().unwrap();
        for call in calls.iter() {
            assert!(
                call.args.iter().all(|a| !a.contains(SENTINEL)),
                "the secret must never appear in child process argv at any step: {:?}",
                call.args
            );
            assert!(
                call.args.iter().all(|a| !a.contains(&encoded)),
                "the base64-encoded secret must never appear in child process argv at any step: {:?}",
                call.args
            );
        }
    }

    // ── AC2: byte-for-byte round trip of spaces/quotes/newlines/non-ASCII ──

    #[tokio::test]
    async fn round_trips_secret_with_spaces_quotes_and_embedded_newlines() {
        let host = TestHost::new();
        let backend = KeychainBackend::new(host.clone());
        let secret = "hello \"world\" 'quoted'\nmiddle line\nend";
        backend.store("spaces-quotes-id", secret).await.unwrap();
        let retrieved = backend.retrieve("spaces-quotes-id").await.unwrap();
        assert_eq!(retrieved, secret);
    }

    #[tokio::test]
    async fn round_trips_non_ascii_secret_byte_for_byte() {
        let host = TestHost::new();
        let backend = KeychainBackend::new(host.clone());
        let secret = "pässwörd-日本語-emoji-🔐-Ñoño";
        backend.store("non-ascii-id", secret).await.unwrap();
        let retrieved = backend.retrieve("non-ascii-id").await.unwrap();
        assert_eq!(retrieved, secret);
    }

    #[tokio::test]
    async fn round_trips_id_containing_spaces_and_quotes() {
        // The id (not just the secret) must survive `security -i`'s own
        // tokenizer once embedded in the service-name token.
        let host = TestHost::new();
        let backend = KeychainBackend::new(host.clone());
        let id = "my id with \"quotes\" and \\backslash";
        backend.store(id, "value").await.unwrap();
        assert!(backend.exists(id).await.unwrap());
        assert_eq!(backend.retrieve(id).await.unwrap(), "value");
    }

    #[tokio::test]
    async fn store_quotes_the_secret_token_so_an_empty_secret_cannot_hang() {
        // A bare trailing `-w` flips `security` into its interactive getpass
        // prompt; quoting guarantees a value token even for "".
        let host = TestHost::new();
        let backend = KeychainBackend::new(host.clone());
        backend.store("empty-id", "").await.unwrap();

        {
            // Scoped: exists() below records into the same calls mutex, so
            // the guard must drop before that call.
            let calls = host.calls.lock().expect("calls lock");
            let stdin = calls
                .iter()
                .find_map(|c| c.stdin.as_ref())
                .expect("store must pass a stdin script");
            let script = String::from_utf8(stdin.clone()).expect("script is UTF-8");
            assert!(
                script.contains("-w \"\""),
                "empty secret must still produce a quoted value token, got: {script}"
            );
        }
        assert!(backend.exists("empty-id").await.unwrap());
    }

    #[tokio::test]
    async fn store_locked_keychain_reports_backend_locked() {
        // Same locked-signature mapping retrieve/delete/exists already have;
        // stderr is read for detection but never embedded in the message.
        let host = Arc::new(LockedKeychainHost {
            inner: TestHost::new(),
        });
        let err = KeychainBackend::new(host)
            .store("id", "secret")
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                VaultError::BackendLocked {
                    interactive: true,
                    ..
                }
            ),
            "expected BackendLocked, got {err:?}"
        );
    }

    // ── Security regression: an id containing a newline must never reach
    // `security -i`'s stdin command stream — it has no escape for `\n`/`\r`,
    // so an unescaped newline in `id` would terminate the current command
    // and let the remainder of `id` be interpreted as one or more injected
    // `security -i` subcommands ────────────────────────────────────────────

    #[tokio::test]
    async fn store_rejects_id_with_embedded_newline_before_any_exec() {
        let host = TestHost::new();
        let backend = KeychainBackend::new(host.clone());
        let err = backend
            .store("evil\nid", "value")
            .await
            .expect_err("an id with an embedded newline must be rejected");
        assert!(matches!(err, VaultError::Other(_)), "got {err:?}");
        assert!(
            host.calls.lock().unwrap().is_empty(),
            "no subprocess should be spawned when the id is rejected"
        );
    }

    #[tokio::test]
    async fn retrieve_rejects_id_with_embedded_carriage_return_before_any_exec() {
        let host = TestHost::new();
        let backend = KeychainBackend::new(host.clone());
        let err = backend
            .retrieve("evil\rid")
            .await
            .expect_err("an id with an embedded carriage return must be rejected");
        assert!(matches!(err, VaultError::Other(_)), "got {err:?}");
        assert!(host.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn delete_rejects_id_with_embedded_newline_before_any_exec() {
        let host = TestHost::new();
        let backend = KeychainBackend::new(host.clone());
        let err = backend
            .delete("evil\nid")
            .await
            .expect_err("an id with an embedded newline must be rejected");
        assert!(matches!(err, VaultError::Other(_)), "got {err:?}");
        assert!(host.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn exists_rejects_id_with_embedded_newline_before_any_exec() {
        let host = TestHost::new();
        let backend = KeychainBackend::new(host.clone());
        let err = backend
            .exists("evil\nid")
            .await
            .expect_err("an id with an embedded newline must be rejected");
        assert!(matches!(err, VaultError::Other(_)), "got {err:?}");
        assert!(host.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn store_rejects_id_with_embedded_nul_before_any_exec() {
        let host = TestHost::new();
        let backend = KeychainBackend::new(host.clone());
        let err = backend
            .store("evil\0id", "value")
            .await
            .expect_err("an id with an embedded NUL byte must be rejected");
        assert!(matches!(err, VaultError::Other(_)), "got {err:?}");
        assert!(host.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn store_rejects_an_injection_shaped_id_with_zero_exec_calls() {
        // Shaped like a real attack: the newline-delimited "second command"
        // would, if it ever reached `security -i`, delete an unrelated
        // entry and then add an attacker-controlled one. Proves not just
        // that the call is rejected, but that *no* exec of any kind runs —
        // so the injected subcommand text never has a chance to execute.
        let host = TestHost::new();
        let backend = KeychainBackend::new(host.clone());
        let injection_id = "a\"\ndelete-generic-password -s other -a x\nadd-generic-password -a x -s other -w evil";
        let err = backend
            .store(injection_id, "value")
            .await
            .expect_err("an injection-shaped id must be rejected");
        assert!(matches!(err, VaultError::Other(_)), "got {err:?}");
        assert!(
            host.calls.lock().unwrap().is_empty(),
            "zero exec calls must occur for a rejected injection-shaped id"
        );
    }

    // ── AC3: retrieve/delete/exists/list are plain exec calls ──────────────

    #[tokio::test]
    async fn retrieve_delete_exists_are_plain_argv_exec_calls() {
        let host = TestHost::new();
        let backend = KeychainBackend::new(host.clone());
        backend.store("plain-id", "value").await.unwrap();

        host.calls.lock().unwrap().clear();
        assert_eq!(backend.retrieve("plain-id").await.unwrap(), "value");
        assert!(backend.exists("plain-id").await.unwrap());
        backend.delete("plain-id").await.unwrap();

        let calls = host.calls.lock().unwrap();
        assert_eq!(calls.len(), 3);
        for call in calls.iter() {
            assert_ne!(
                call.args.first().map(String::as_str),
                Some("-i"),
                "retrieve/exists/delete must never use interactive mode: {:?}",
                call.args
            );
            assert!(
                call.stdin.is_none(),
                "retrieve/exists/delete must not carry stdin: {:?}",
                call.args
            );
        }
    }

    #[tokio::test]
    async fn list_parses_plain_and_hex_escaped_dump_keychain_entries() {
        let host = TestHost::new();
        let backend = KeychainBackend::new(host.clone());
        backend.store("alpha", "val-a").await.unwrap();
        backend
            .store("awkward name: with spaces", "val-b")
            .await
            .unwrap();
        backend.store("日本語-emoji-🔐", "val-c").await.unwrap();

        let mut ids = backend.list().await.unwrap();
        ids.sort();
        let mut expected = vec!["alpha", "awkward name: with spaces", "日本語-emoji-🔐"];
        expected.sort_unstable();
        assert_eq!(ids, expected);
    }

    #[tokio::test]
    async fn list_round_trips_an_id_with_an_embedded_double_quote() {
        // Regression for the store/list asymmetry: store() supports ids with
        // embedded double quotes (escaped for `security -i`'s tokenizer),
        // but real `security dump-keychain`'s plain-quoted display form
        // embeds a `"` in the id raw and unescaped (verified empirically —
        // see `parse_service_attribute_line` doc comment), so list()'s
        // parser must not stop at the *first* embedded quote.
        let host = TestHost::new();
        let backend = KeychainBackend::new(host.clone());
        let id = r#"has "quotes" inside"#;
        backend.store(id, "value").await.unwrap();

        let ids = backend.list().await.unwrap();
        assert_eq!(
            ids,
            vec![id.to_string()],
            "list() must recover the full id, not truncate at the first embedded quote"
        );
    }

    #[tokio::test]
    async fn list_round_trips_an_id_ending_in_a_double_quote() {
        // Edge case of the same asymmetry: when the id itself ends in `"`,
        // the dumped line ends with two consecutive `"` characters (the
        // embedded one, then the true closing delimiter) — verified
        // empirically against the real `security` binary. Parsing from the
        // *last* quote correctly recovers the trailing embedded quote.
        let host = TestHost::new();
        let backend = KeychainBackend::new(host.clone());
        let id = r#"ends with quote""#;
        backend.store(id, "value").await.unwrap();

        let ids = backend.list().await.unwrap();
        assert_eq!(ids, vec![id.to_string()]);
    }

    #[test]
    fn parse_service_attribute_line_recovers_id_with_embedded_quote_not_truncated() {
        // Captured line shape verified empirically against the real
        // `security` binary: storing an id of `has "quotes" inside` dumps
        // as exactly this line, with the embedded quotes unescaped.
        let line = r#"    0x00000007 <blob>="vaultkeeper:has "quotes" inside""#;
        let parsed = KeychainBackend::parse_service_attribute_line(line);
        assert_eq!(
            parsed,
            Some("vaultkeeper:has \"quotes\" inside".to_string()),
            "must not truncate at the first embedded quote"
        );
    }

    #[test]
    fn parse_service_attribute_line_recovers_id_ending_in_a_quote() {
        // Captured line shape verified empirically: storing an id of
        // `ends with quote"` dumps with the line ending in two consecutive
        // `"` characters.
        let line = r#"    0x00000007 <blob>="vaultkeeper:ends with quote"""#;
        let parsed = KeychainBackend::parse_service_attribute_line(line);
        assert_eq!(
            parsed,
            Some("vaultkeeper:ends with quote\"".to_string()),
            "must recover the trailing embedded quote, not treat it as the closing delimiter"
        );
    }

    #[test]
    fn parse_dump_ids_matches_ts_backend_output_shape() {
        // Mirrors the fixture in
        // packages/vaultkeeper/test/unit/backend/keychain-backend.test.ts
        let stdout = [
            "keychain: \"/test/login.keychain-db\"",
            "attributes:",
            "    0x00000007 <blob>=\"vaultkeeper:my-secret\"",
            "    0x00000008 <blob>=<NULL>",
            "attributes:",
            "    0x00000007 <blob>=\"vaultkeeper:another-secret\"",
        ]
        .join("\n");

        let ids = KeychainBackend::parse_dump_ids(&stdout);
        assert_eq!(ids, vec!["my-secret", "another-secret"]);
    }

    #[test]
    fn parse_dump_ids_ignores_entries_without_the_vaultkeeper_prefix() {
        let stdout = "    0x00000007 <blob>=\"some-other-app:unrelated\"\n";
        let ids = KeychainBackend::parse_dump_ids(stdout);
        assert!(ids.is_empty());
    }

    #[tokio::test]
    async fn list_returns_empty_when_dump_keychain_fails() {
        struct FailingDumpHost {
            inner: Arc<TestHost>,
        }

        #[async_trait::async_trait]
        impl HostPlatform for FailingDumpHost {
            async fn exec(
                &self,
                cmd: &str,
                args: &[&str],
                options: ExecOptions<'_>,
            ) -> Result<ExecOutput, VaultError> {
                if args.first().copied() == Some("dump-keychain") {
                    return Ok(ExecOutput {
                        stdout: Vec::new(),
                        stderr: b"keychain locked".to_vec(),
                        exit_code: 1,
                    });
                }
                self.inner.exec(cmd, args, options).await
            }
            async fn read_file(&self, p: &Path) -> Result<Vec<u8>, VaultError> {
                self.inner.read_file(p).await
            }
            async fn write_file(&self, p: &Path, c: &[u8], m: u32) -> Result<(), VaultError> {
                self.inner.write_file(p, c, m).await
            }
            async fn file_exists(&self, p: &Path) -> Result<bool, VaultError> {
                self.inner.file_exists(p).await
            }
            async fn delete_file(&self, p: &Path) -> Result<(), VaultError> {
                self.inner.delete_file(p).await
            }
            async fn list_dir(&self, p: &Path) -> Result<Vec<String>, VaultError> {
                self.inner.list_dir(p).await
            }
            fn platform(&self) -> Platform {
                self.inner.platform()
            }
            fn config_dir(&self) -> &Path {
                self.inner.config_dir()
            }
        }

        let host = Arc::new(FailingDumpHost {
            inner: TestHost::new(),
        });
        let backend = KeychainBackend::new(host);
        assert_eq!(backend.list().await.unwrap(), Vec::<String>::new());
    }

    // ── AC4 (negative): missing entries and exec failures surface typed
    // errors, never a partial/garbage secret ───────────────────────────────

    #[tokio::test]
    async fn retrieve_missing_returns_secret_not_found() {
        let host = TestHost::new();
        let backend = KeychainBackend::new(host);
        let err = backend.retrieve("nonexistent").await.unwrap_err();
        assert!(
            matches!(err, VaultError::SecretNotFound { .. }),
            "expected SecretNotFound, got {err:?}"
        );
    }

    #[tokio::test]
    async fn delete_missing_returns_secret_not_found() {
        let host = TestHost::new();
        let backend = KeychainBackend::new(host);
        let err = backend.delete("nonexistent").await.unwrap_err();
        assert!(
            matches!(err, VaultError::SecretNotFound { .. }),
            "expected SecretNotFound, got {err:?}"
        );
    }

    #[tokio::test]
    async fn exists_returns_false_for_missing_and_true_for_present() {
        let host = TestHost::new();
        let backend = KeychainBackend::new(host);
        assert!(!backend.exists("nonexistent").await.unwrap());
        backend.store("present-id", "value").await.unwrap();
        assert!(backend.exists("present-id").await.unwrap());
    }

    // ── Locked keychain: retrieve/delete/exists must report BackendLocked,
    // not misreport a locked keychain as a missing secret. Signature is the
    // documented Apple `SecCopyErrorMessageString` text for
    // `errSecInteractionNotAllowed` (-25308); see
    // `KeychainBackend::LOCKED_KEYCHAIN_STDERR_SIGNATURE`'s doc comment for
    // why this couldn't be captured against a genuinely locked real keychain
    // in this environment (it blocks on an interactive unlock prompt
    // instead of failing fast) ───────────────────────────────────────────

    /// Wraps [`TestHost`] and, for `find-generic-password` /
    /// `delete-generic-password`, always answers with the documented
    /// `errSecInteractionNotAllowed` stderr signature instead of delegating,
    /// simulating a locked keychain that can't be read non-interactively.
    struct LockedKeychainHost {
        inner: Arc<TestHost>,
    }

    #[async_trait::async_trait]
    impl HostPlatform for LockedKeychainHost {
        async fn exec(
            &self,
            cmd: &str,
            args: &[&str],
            options: ExecOptions<'_>,
        ) -> Result<ExecOutput, VaultError> {
            match args.first().copied() {
                Some("find-generic-password") | Some("delete-generic-password") | Some("-i") => Ok(ExecOutput {
                    stdout: Vec::new(),
                    stderr: b"security: SecKeychainFindGenericPassword: User interaction is not allowed."
                        .to_vec(),
                    exit_code: 36,
                }),
                _ => self.inner.exec(cmd, args, options).await,
            }
        }
        async fn read_file(&self, p: &Path) -> Result<Vec<u8>, VaultError> {
            self.inner.read_file(p).await
        }
        async fn write_file(&self, p: &Path, c: &[u8], m: u32) -> Result<(), VaultError> {
            self.inner.write_file(p, c, m).await
        }
        async fn file_exists(&self, p: &Path) -> Result<bool, VaultError> {
            self.inner.file_exists(p).await
        }
        async fn delete_file(&self, p: &Path) -> Result<(), VaultError> {
            self.inner.delete_file(p).await
        }
        async fn list_dir(&self, p: &Path) -> Result<Vec<String>, VaultError> {
            self.inner.list_dir(p).await
        }
        fn platform(&self) -> Platform {
            self.inner.platform()
        }
        fn config_dir(&self) -> &Path {
            self.inner.config_dir()
        }
    }

    #[tokio::test]
    async fn retrieve_on_locked_keychain_returns_backend_locked_not_secret_not_found() {
        let host = Arc::new(LockedKeychainHost {
            inner: TestHost::new(),
        });
        let err = KeychainBackend::new(host)
            .retrieve("some-id")
            .await
            .expect_err("a locked keychain must not report success");
        assert!(
            matches!(
                err,
                VaultError::BackendLocked {
                    interactive: true,
                    ..
                }
            ),
            "expected BackendLocked, got {err:?}"
        );
    }

    #[tokio::test]
    async fn delete_on_locked_keychain_returns_backend_locked_not_secret_not_found() {
        let host = Arc::new(LockedKeychainHost {
            inner: TestHost::new(),
        });
        let err = KeychainBackend::new(host)
            .delete("some-id")
            .await
            .expect_err("a locked keychain must not report success");
        assert!(
            matches!(
                err,
                VaultError::BackendLocked {
                    interactive: true,
                    ..
                }
            ),
            "expected BackendLocked, got {err:?}"
        );
    }

    #[tokio::test]
    async fn exists_on_locked_keychain_returns_backend_locked_not_false() {
        let host = Arc::new(LockedKeychainHost {
            inner: TestHost::new(),
        });
        let err = KeychainBackend::new(host)
            .exists("some-id")
            .await
            .expect_err("a locked keychain must not silently report 'does not exist'");
        assert!(
            matches!(
                err,
                VaultError::BackendLocked {
                    interactive: true,
                    ..
                }
            ),
            "expected BackendLocked, got {err:?}"
        );
    }

    #[tokio::test]
    async fn an_unrecognized_non_zero_exit_still_reports_secret_not_found() {
        // Parity guard: only the specific locked-keychain stderr signature
        // is special-cased. Every other non-zero exit (e.g. a genuinely
        // missing entry) must still map to SecretNotFound, matching the TS
        // backend and this backend's pre-existing behavior.
        let host = TestHost::new();
        let backend = KeychainBackend::new(host);
        let err = backend.retrieve("truly-missing").await.unwrap_err();
        assert!(
            matches!(err, VaultError::SecretNotFound { .. }),
            "expected SecretNotFound for an ordinary missing entry, got {err:?}"
        );
    }

    #[tokio::test]
    async fn store_failure_surfaces_typed_error_not_panic() {
        struct FailingHost {
            inner: Arc<TestHost>,
        }

        #[async_trait::async_trait]
        impl HostPlatform for FailingHost {
            async fn exec(
                &self,
                _cmd: &str,
                _args: &[&str],
                _options: ExecOptions<'_>,
            ) -> Result<ExecOutput, VaultError> {
                Ok(ExecOutput {
                    stdout: Vec::new(),
                    stderr: b"security: SecKeychainItemCreateFromContent: keychain locked".to_vec(),
                    exit_code: 45,
                })
            }
            async fn read_file(&self, p: &Path) -> Result<Vec<u8>, VaultError> {
                self.inner.read_file(p).await
            }
            async fn write_file(&self, p: &Path, c: &[u8], m: u32) -> Result<(), VaultError> {
                self.inner.write_file(p, c, m).await
            }
            async fn file_exists(&self, p: &Path) -> Result<bool, VaultError> {
                self.inner.file_exists(p).await
            }
            async fn delete_file(&self, p: &Path) -> Result<(), VaultError> {
                self.inner.delete_file(p).await
            }
            async fn list_dir(&self, p: &Path) -> Result<Vec<String>, VaultError> {
                self.inner.list_dir(p).await
            }
            fn platform(&self) -> Platform {
                self.inner.platform()
            }
            fn config_dir(&self) -> &Path {
                self.inner.config_dir()
            }
        }

        let host = Arc::new(FailingHost {
            inner: TestHost::new(),
        });
        let err = KeychainBackend::new(host)
            .store("id", "secret")
            .await
            .unwrap_err();
        assert!(
            matches!(err, VaultError::Exec { ref command, .. } if command == "security"),
            "expected VaultError::Exec carrying the failing command, got {err:?}"
        );
    }

    #[tokio::test]
    async fn store_failure_never_embeds_raw_stderr_in_the_error_message() {
        // Unlike every other error path in this file, store()'s error
        // message must never echo `security`'s stderr verbatim: it's the
        // one subprocess whose stdin carries the secret, so an
        // unanticipated future `security` error mode that echoes its input
        // back on stderr must not have a path into a `VaultError` message
        // that could get logged. Fake a stderr that would fail this test if
        // it leaked through — including the base64 form of a sentinel
        // secret, mirroring how the real secret is encoded before it's
        // embedded in the -i script.
        struct EchoingStderrHost {
            inner: Arc<TestHost>,
        }

        const SENTINEL: &str = "store-error-sentinel-should-never-leak-into-message";

        #[async_trait::async_trait]
        impl HostPlatform for EchoingStderrHost {
            async fn exec(
                &self,
                _cmd: &str,
                _args: &[&str],
                _options: ExecOptions<'_>,
            ) -> Result<ExecOutput, VaultError> {
                let encoded = Base64::encode_string(SENTINEL.as_bytes());
                Ok(ExecOutput {
                    stdout: Vec::new(),
                    stderr: format!(
                        "security: unexpected error near `add-generic-password -a vaultkeeper \
                         -s \"vaultkeeper:id\" -w {encoded}`"
                    )
                    .into_bytes(),
                    exit_code: 1,
                })
            }
            async fn read_file(&self, p: &Path) -> Result<Vec<u8>, VaultError> {
                self.inner.read_file(p).await
            }
            async fn write_file(&self, p: &Path, c: &[u8], m: u32) -> Result<(), VaultError> {
                self.inner.write_file(p, c, m).await
            }
            async fn file_exists(&self, p: &Path) -> Result<bool, VaultError> {
                self.inner.file_exists(p).await
            }
            async fn delete_file(&self, p: &Path) -> Result<(), VaultError> {
                self.inner.delete_file(p).await
            }
            async fn list_dir(&self, p: &Path) -> Result<Vec<String>, VaultError> {
                self.inner.list_dir(p).await
            }
            fn platform(&self) -> Platform {
                self.inner.platform()
            }
            fn config_dir(&self) -> &Path {
                self.inner.config_dir()
            }
        }

        let host = Arc::new(EchoingStderrHost {
            inner: TestHost::new(),
        });
        let err = KeychainBackend::new(host)
            .store("id", SENTINEL)
            .await
            .unwrap_err();
        let message = err.to_string();
        let encoded = Base64::encode_string(SENTINEL.as_bytes());
        assert!(
            !message.contains(SENTINEL) && !message.contains(&encoded),
            "store()'s error message must never embed raw stderr (which could carry the \
             secret or its base64 encoding): {message:?}"
        );
    }

    #[tokio::test]
    async fn retrieve_surfaces_typed_error_on_malformed_base64_not_garbage_secret() {
        struct GarbageHost {
            inner: Arc<TestHost>,
        }

        #[async_trait::async_trait]
        impl HostPlatform for GarbageHost {
            async fn exec(
                &self,
                cmd: &str,
                args: &[&str],
                options: ExecOptions<'_>,
            ) -> Result<ExecOutput, VaultError> {
                if args.first().copied() == Some("find-generic-password") {
                    return Ok(ExecOutput {
                        stdout: b"not-valid-base64!!!\n".to_vec(),
                        stderr: Vec::new(),
                        exit_code: 0,
                    });
                }
                self.inner.exec(cmd, args, options).await
            }
            async fn read_file(&self, p: &Path) -> Result<Vec<u8>, VaultError> {
                self.inner.read_file(p).await
            }
            async fn write_file(&self, p: &Path, c: &[u8], m: u32) -> Result<(), VaultError> {
                self.inner.write_file(p, c, m).await
            }
            async fn file_exists(&self, p: &Path) -> Result<bool, VaultError> {
                self.inner.file_exists(p).await
            }
            async fn delete_file(&self, p: &Path) -> Result<(), VaultError> {
                self.inner.delete_file(p).await
            }
            async fn list_dir(&self, p: &Path) -> Result<Vec<String>, VaultError> {
                self.inner.list_dir(p).await
            }
            fn platform(&self) -> Platform {
                self.inner.platform()
            }
            fn config_dir(&self) -> &Path {
                self.inner.config_dir()
            }
        }

        let host = Arc::new(GarbageHost {
            inner: TestHost::new(),
        });
        let err = KeychainBackend::new(host).retrieve("id").await.unwrap_err();
        assert!(
            matches!(err, VaultError::Other(_)),
            "expected a typed error (never a garbage secret), got {err:?}"
        );
    }

    // ── Additional coverage: is_available/backend_type/display_name ────────

    #[tokio::test]
    async fn is_available_false_on_non_darwin_platform() {
        let host = Arc::new(TestHost {
            config_dir: PathBuf::from("/test/config"),
            entries: Mutex::new(std::collections::HashMap::new()),
            calls: Mutex::new(Vec::new()),
            list_keychains_unavailable: false,
            platform: Platform::Linux,
        });
        let backend = KeychainBackend::new(host);
        assert!(!backend.is_available().await);
    }

    #[tokio::test]
    async fn is_available_true_on_darwin_when_security_responds() {
        let host = TestHost::new();
        let backend = KeychainBackend::new(host);
        assert!(backend.is_available().await);
    }

    #[tokio::test]
    async fn is_available_false_when_security_not_installed() {
        let host = Arc::new(TestHost {
            config_dir: PathBuf::from("/test/config"),
            entries: Mutex::new(std::collections::HashMap::new()),
            calls: Mutex::new(Vec::new()),
            list_keychains_unavailable: true,
            platform: Platform::Darwin,
        });
        let backend = KeychainBackend::new(host);
        assert!(!backend.is_available().await);
    }

    #[test]
    fn backend_type_and_display_name() {
        let host = TestHost::new();
        let backend = KeychainBackend::new(host);
        assert_eq!(backend.backend_type(), "keychain");
        assert_eq!(backend.display_name(), "macOS Keychain");
    }
}
