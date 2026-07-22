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
//! base64-encoding the secret before it enters the stdin script is *load
//! -bearing* and is kept unchanged from the TS backend: the base64 alphabet
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
//! correctly through `security -i`. An embedded newline in `<id>` is not
//! escaped by this scheme (it would prematurely terminate the `-i` command
//! line) — `id` values are expected to be single-line identifiers, as they
//! are everywhere else in vaultkeeper.
//!
//! ## Coordination with #270
//!
//! The TS `KeychainBackend`'s argv leak is also tracked as standalone defect
//! #270. This Rust-core port supersedes it with the `security -i` design
//! described above; #270 is left open to apply the equivalent fix to the TS
//! implementation, which this PR does not touch.

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
    /// - Plain quoted form (fully printable ASCII): `="<value>"`.
    /// - Hex + octal-escaped display form (any byte outside printable ASCII,
    ///   including `\`): `=0x<HEX>  "<octal-escaped display>"` — the hex
    ///   digits are the authoritative raw bytes; the quoted text afterwards
    ///   is only a lossy human-readable rendering, so this parses the hex
    ///   form when present rather than the ambiguous quoted display.
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
            let end = quoted.find('"')?;
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
        let script = format!(
            "delete-generic-password -a {account_token} -s {service_token}\n\
             add-generic-password -a {account_token} -s {service_token} -w {encoded}\n"
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
            return Err(VaultError::Exec {
                message: format!(
                    "security add-generic-password failed with exit code {}: {}",
                    output.exit_code,
                    String::from_utf8_lossy(&output.stderr)
                ),
                command: "security".to_string(),
            });
        }
        Ok(())
    }

    async fn retrieve(&self, id: &str) -> Result<String, VaultError> {
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
            return Err(VaultError::SecretNotFound {
                message: format!("Secret not found in macOS Keychain: {id}"),
            });
        }
        Ok(())
    }

    async fn exists(&self, id: &str) -> Result<bool, VaultError> {
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
