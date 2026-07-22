//! Windows DPAPI backend, driven via PowerShell over [`HostPlatform::exec`].
//!
//! Ports the TypeScript `DpapiBackend`
//! (`packages/vaultkeeper/src/backend/dpapi-backend.ts`) into
//! `vaultkeeper-core`, inheriting its stdin secret-delivery fix from day one
//! (issue #269 / TS PR #272) rather than re-deriving it: the secret is
//! base64-encoded and piped to PowerShell over stdin, read via
//! `[Console]::In.ReadToEnd()` inside the script, and decoded there before
//! `ProtectedData.Protect`. The secret never appears in the `-Command`
//! script text, which is what would otherwise land it in this process's
//! child argv (and, with Windows command-line auditing enabled, in the
//! Security event log — the original defect, #269).
//!
//! ## On-disk format compatibility
//!
//! Entries written by either implementation are mutually readable:
//! - Same entry-path scheme: `<storageDir>/<hex(id)>.enc`, matching the TS
//!   backend's `getEntryPath` byte-for-byte.
//! - Same DPAPI envelope: the raw `CurrentUser`-scope `ProtectedData.Protect`
//!   output, written directly to the entry file with no additional wrapping
//!   — `[System.IO.File]::WriteAllBytes(path, $encrypted)`, matching the TS
//!   script exactly.
//!
//! The `retrieve` script's *stdout* encoding is not part of that shared
//! on-disk contract (it is purely an implementation-internal channel: no
//! other implementation ever reads it), so this port deliberately diverges
//! from the TS script's `Write-Output ([Text.Encoding]::UTF8.GetString(...))`
//! and instead base64-encodes the decrypted bytes onto stdout. This avoids
//! the same category of risk the stdin fix addressed on the way in —
//! terminal/console text-encoding and newline-translation surprises — on the
//! way out, and is what makes AC2's byte-for-byte round trip (including
//! embedded newlines) hold unconditionally rather than depending on
//! PowerShell console encoding configuration.

use crate::backend::types::{ExecOptions, HostPlatform, ListableBackend, Platform, SecretBackend};
use crate::errors::VaultError;
use base64ct::{Base64, Encoding};
use std::path::PathBuf;
use std::sync::Arc;
use zeroize::Zeroizing;

use super::file::hex_encode;

/// Subdirectory (of the host config dir) holding DPAPI-encrypted blobs when
/// no `BackendConfig.path` override is configured. Mirrors the TS backend's
/// `$HOME/.vaultkeeper/dpapi` default in spirit (same leaf directory name),
/// adapted to this crate's `HostPlatform::config_dir` convention (see
/// `FileBackend::storage_dir`, which uses the same pattern for `file/`).
const DEFAULT_DIR_NAME: &str = "dpapi";

/// Windows Data Protection API secret backend.
///
/// Only meaningfully available on Windows (`is_available` checks
/// [`Platform::Windows`] and that `powershell` can load
/// `System.Security.Cryptography.ProtectedData`). Encrypted blobs are stored
/// under `<config_dir>/dpapi/` by default, or under `BackendConfig.path` when
/// configured (see the registration site for how that is threaded through).
pub struct DpapiBackend {
    host: Arc<dyn HostPlatform>,
    storage_dir: Option<PathBuf>,
}

impl DpapiBackend {
    /// Create a new `DpapiBackend`.
    ///
    /// `storage_dir` is sourced from `BackendConfig.path` by the registry
    /// factory; `None` falls back to `<config_dir>/dpapi`, mirroring the TS
    /// backend's `resolveStorageDir`.
    pub fn new(host: Arc<dyn HostPlatform>, storage_dir: Option<PathBuf>) -> Self {
        Self { host, storage_dir }
    }

    fn storage_dir(&self) -> PathBuf {
        match &self.storage_dir {
            Some(dir) => dir.clone(),
            None => self.host.config_dir().join(DEFAULT_DIR_NAME),
        }
    }

    fn entry_path(&self, id: &str) -> PathBuf {
        let safe_id = hex_encode(id.as_bytes());
        self.storage_dir().join(format!("{safe_id}.enc"))
    }

    /// Force creation of the storage directory by writing a sentinel file
    /// through the host (mirrors `FileBackend::ensure_storage_dir`) — the
    /// entry file itself is written by the PowerShell child process, not
    /// through `HostPlatform::write_file`, so this is the only place that
    /// guarantees the directory exists before that child process runs.
    async fn ensure_storage_dir(&self) -> Result<(), VaultError> {
        let sentinel = self.storage_dir().join(".keep");
        if !self.host.file_exists(&sentinel).await.unwrap_or(false) {
            self.host.write_file(&sentinel, b"", 0o600).await?;
        }
        Ok(())
    }

    /// Encode `path` as a PowerShell double-quoted string literal.
    ///
    /// Reuses JSON string escaping (backslash/quote escaping is a superset
    /// compatible with what a PowerShell double-quoted string needs for a
    /// filesystem path), matching the TS backend's
    /// `JSON.stringify(entryPath)` byte-for-byte.
    fn ps_string_literal(path: &std::path::Path) -> Result<String, VaultError> {
        serde_json::to_string(&path.to_string_lossy().into_owned())
            .map_err(|e| VaultError::Other(format!("failed to encode entry path: {e}")))
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl SecretBackend for DpapiBackend {
    fn backend_type(&self) -> &str {
        "dpapi"
    }

    fn display_name(&self) -> &str {
        "Windows DPAPI"
    }

    async fn is_available(&self) -> bool {
        if self.host.platform() != Platform::Windows {
            return false;
        }
        match self
            .host
            .exec(
                "powershell",
                &[
                    "-NoProfile",
                    "-Command",
                    "[System.Security.Cryptography.ProtectedData] | Out-Null; exit 0",
                ],
                ExecOptions::default(),
            )
            .await
        {
            Ok(output) => output.exit_code == 0,
            Err(_) => false,
        }
    }

    async fn store(&self, id: &str, secret: &str) -> Result<(), VaultError> {
        self.ensure_storage_dir().await?;
        let entry_path = self.entry_path(id);
        let entry_literal = Self::ps_string_literal(&entry_path)?;

        // The secret is never embedded in the script text (which becomes a
        // `-Command` argv element and is therefore visible to any other
        // process that can list this process's command line, e.g.
        // `ps`/Task Manager). Instead it is piped over stdin, base64-encoded
        // so the transfer is immune to console/pipe text-encoding and
        // newline-translation differences (issue #269).
        let script = [
            "Add-Type -AssemblyName System.Security".to_string(),
            "$b64 = [Console]::In.ReadToEnd()".to_string(),
            "$bytes = [System.Convert]::FromBase64String($b64.Trim())".to_string(),
            "$entropy = $null".to_string(),
            "$scope = [System.Security.Cryptography.DataProtectionScope]::CurrentUser"
                .to_string(),
            "$encrypted = [System.Security.Cryptography.ProtectedData]::Protect($bytes, $entropy, $scope)"
                .to_string(),
            format!("[System.IO.File]::WriteAllBytes({entry_literal}, $encrypted)"),
        ]
        .join("; ");

        // Zero the base64 intermediate once the exec call returns (security
        // rule: zero buffers containing secret-derived material after use).
        let stdin_payload = Zeroizing::new(Base64::encode_string(secret.as_bytes()));

        let output = self
            .host
            .exec(
                "powershell",
                &["-NoProfile", "-Command", &script],
                ExecOptions {
                    stdin: Some(stdin_payload.as_bytes()),
                    ..Default::default()
                },
            )
            .await?;

        if output.exit_code != 0 {
            return Err(VaultError::Exec {
                message: format!(
                    "DPAPI encrypt failed with exit code {}: {}",
                    output.exit_code,
                    String::from_utf8_lossy(&output.stderr)
                ),
                command: "powershell".to_string(),
            });
        }
        Ok(())
    }

    async fn retrieve(&self, id: &str) -> Result<String, VaultError> {
        let entry_path = self.entry_path(id);

        match self.host.file_exists(&entry_path).await {
            Ok(true) => {}
            Ok(false) => {
                return Err(VaultError::SecretNotFound {
                    message: format!("Secret not found in Windows DPAPI store: {id}"),
                });
            }
            Err(e) => return Err(e),
        }

        let entry_literal = Self::ps_string_literal(&entry_path)?;

        // See the module docs: unlike the TS reference script, the decrypted
        // bytes are base64-encoded onto stdout rather than written as raw
        // UTF-8 text, so this port's byte-for-byte round trip does not
        // depend on PowerShell's console text encoding.
        let script = [
            "Add-Type -AssemblyName System.Security".to_string(),
            format!("$encrypted = [System.IO.File]::ReadAllBytes({entry_literal})"),
            "$entropy = $null".to_string(),
            "$scope = [System.Security.Cryptography.DataProtectionScope]::CurrentUser"
                .to_string(),
            "$bytes = [System.Security.Cryptography.ProtectedData]::Unprotect($encrypted, $entropy, $scope)"
                .to_string(),
            "[Console]::Out.Write([System.Convert]::ToBase64String($bytes))".to_string(),
        ]
        .join("; ");

        let output = self
            .host
            .exec(
                "powershell",
                &["-NoProfile", "-Command", &script],
                ExecOptions::default(),
            )
            .await?;

        // Any non-zero exit here means Unprotect itself failed — the
        // canonical cause is a corrupted/truncated blob (AC4), since a
        // missing entry was already ruled out above. Never fall through to
        // returning partial/garbage stdout as a secret.
        if output.exit_code != 0 {
            return Err(VaultError::Decryption {
                message: format!(
                    "Failed to decrypt DPAPI entry: {}",
                    String::from_utf8_lossy(&output.stderr)
                ),
                path: entry_path.display().to_string(),
            });
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let decoded = Base64::decode_vec(stdout.trim()).map_err(|e| VaultError::Decryption {
            message: format!("DPAPI decrypt output was not valid base64: {e}"),
            path: entry_path.display().to_string(),
        })?;
        String::from_utf8(decoded).map_err(|e| VaultError::Decryption {
            message: format!("Decrypted DPAPI entry is not valid UTF-8: {e}"),
            path: entry_path.display().to_string(),
        })
    }

    async fn delete(&self, id: &str) -> Result<(), VaultError> {
        let entry_path = self.entry_path(id);
        match self.host.file_exists(&entry_path).await {
            Ok(true) => self.host.delete_file(&entry_path).await,
            Ok(false) => Err(VaultError::SecretNotFound {
                message: format!("Secret not found in Windows DPAPI store: {id}"),
            }),
            Err(e) => Err(e),
        }
    }

    async fn exists(&self, id: &str) -> Result<bool, VaultError> {
        self.host.file_exists(&self.entry_path(id)).await
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl ListableBackend for DpapiBackend {
    async fn list(&self) -> Result<Vec<String>, VaultError> {
        let storage_dir = self.storage_dir();
        let filenames = self.host.list_dir(&storage_dir).await?;

        let mut ids = Vec::new();
        for filename in &filenames {
            if let Some(hex_name) = filename.strip_suffix(".enc")
                && let Ok(bytes) = hex_decode(hex_name)
                && let Ok(id) = String::from_utf8(bytes)
            {
                ids.push(id);
            }
        }
        Ok(ids)
    }
}

/// Hex-decode a string back to bytes. Local copy of `file::hex_decode`
/// (private to that module) — kept self-contained rather than widening that
/// module's visibility for a single caller, matching `signing_store`'s
/// documented rationale for not reaching into `file.rs`'s private helpers.
fn hex_decode(hex: &str) -> Result<Vec<u8>, VaultError> {
    if !hex.len().is_multiple_of(2) {
        return Err(VaultError::Other("Invalid hex string length".to_string()));
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let byte = u8::from_str_radix(&hex[i..i + 2], 16)
            .map_err(|e| VaultError::Other(format!("Invalid hex: {e}")))?;
        bytes.push(byte);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::ExecOutput;
    use std::collections::HashMap;
    use std::path::Path;
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

    /// Test double for `HostPlatform` that fakes both the filesystem (an
    /// in-memory map, standing in for the entry files the PowerShell child
    /// process would write/read on a real host sharing the same disk) and
    /// DPAPI's `Protect`/`Unprotect` (a reversible fake transform keyed off
    /// the script text, since no real PowerShell runs in this test).
    struct TestHost {
        config_dir: PathBuf,
        files: Mutex<HashMap<PathBuf, Vec<u8>>>,
        calls: Mutex<Vec<RecordedExec>>,
        platform: Platform,
        version_unavailable: bool,
    }

    /// Magic prefix the fake `Protect` step adds, so the fake `Unprotect`
    /// step can detect a corrupted/truncated blob (AC4) by its absence.
    const FAKE_DPAPI_MAGIC: &[u8] = b"FAKE-DPAPI-PROTECTED:";

    impl TestHost {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                config_dir: PathBuf::from("/test/config"),
                files: Mutex::new(HashMap::new()),
                calls: Mutex::new(Vec::new()),
                platform: Platform::Windows,
                version_unavailable: false,
            })
        }

        /// Extract the JSON-quoted path literal that appears immediately
        /// after `marker` in `script` (e.g. `WriteAllBytes(` or
        /// `ReadAllBytes(`), mirroring how a real PowerShell parser would
        /// consume the same literal `DpapiBackend::ps_string_literal` emits.
        fn extract_path_literal(script: &str, marker: &str) -> PathBuf {
            let after = script.split(marker).nth(1).expect("marker present");
            let quote_start = after.find('"').expect("opening quote");
            let rest = &after[quote_start..];
            // Find the matching unescaped closing quote.
            let mut end = None;
            let bytes = rest.as_bytes();
            let mut i = 1;
            while i < bytes.len() {
                if bytes[i] == b'"' && bytes[i - 1] != b'\\' {
                    end = Some(i);
                    break;
                }
                i += 1;
            }
            let end = end.expect("closing quote");
            let literal = &rest[..=end];
            let decoded: String = serde_json::from_str(literal).expect("valid JSON string");
            PathBuf::from(decoded)
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

            let script = args.get(2).copied().unwrap_or("");

            if script.contains("ProtectedData] | Out-Null") {
                return if self.version_unavailable {
                    Ok(ExecOutput {
                        stdout: Vec::new(),
                        stderr: b"powershell: command not found".to_vec(),
                        exit_code: 127,
                    })
                } else {
                    Ok(ExecOutput {
                        stdout: Vec::new(),
                        stderr: Vec::new(),
                        exit_code: 0,
                    })
                };
            }

            if script.contains("::Protect(") {
                let path = Self::extract_path_literal(script, "WriteAllBytes(");
                let b64 = String::from_utf8(options.stdin.expect("stdin present").to_vec())
                    .expect("valid utf8 stdin");
                let secret_bytes = Base64::decode_vec(b64.trim()).expect("valid base64 stdin");
                // Fake envelope: MAGIC || u32-BE length || secret bytes. The
                // length prefix is what lets the fake `Unprotect` below
                // detect truncation deterministically (real DPAPI/AES-GCM
                // would fail the same way via its auth tag), independent of
                // whether the truncated tail happens to still decode as
                // valid UTF-8.
                let mut encrypted = FAKE_DPAPI_MAGIC.to_vec();
                encrypted.extend_from_slice(&(secret_bytes.len() as u32).to_be_bytes());
                encrypted.extend_from_slice(&secret_bytes);
                self.files.lock().unwrap().insert(path, encrypted);
                return Ok(ExecOutput {
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                    exit_code: 0,
                });
            }

            if script.contains("::Unprotect(") {
                let path = Self::extract_path_literal(script, "ReadAllBytes(");
                let stored = self.files.lock().unwrap().get(&path).cloned();
                let header_len = FAKE_DPAPI_MAGIC.len() + 4;
                return match stored {
                    Some(bytes)
                        if bytes.starts_with(FAKE_DPAPI_MAGIC) && bytes.len() >= header_len =>
                    {
                        let len_bytes: [u8; 4] = bytes[FAKE_DPAPI_MAGIC.len()..header_len]
                            .try_into()
                            .expect("4 bytes");
                        let declared_len = u32::from_be_bytes(len_bytes) as usize;
                        let secret_bytes = &bytes[header_len..];
                        if secret_bytes.len() != declared_len {
                            Ok(ExecOutput {
                                stdout: Vec::new(),
                                stderr: b"Unprotect: the data is invalid (length mismatch)"
                                    .to_vec(),
                                exit_code: 1,
                            })
                        } else {
                            Ok(ExecOutput {
                                stdout: Base64::encode_string(secret_bytes).into_bytes(),
                                stderr: Vec::new(),
                                exit_code: 0,
                            })
                        }
                    }
                    _ => Ok(ExecOutput {
                        stdout: Vec::new(),
                        stderr: b"Unprotect: the data is invalid".to_vec(),
                        exit_code: 1,
                    }),
                };
            }

            panic!("unexpected DPAPI script invocation: {script:?}");
        }

        async fn read_file(&self, path: &Path) -> Result<Vec<u8>, VaultError> {
            self.files
                .lock()
                .unwrap()
                .get(path)
                .cloned()
                .ok_or_else(|| VaultError::Other(format!("Not found: {}", path.display())))
        }

        async fn write_file(
            &self,
            path: &Path,
            content: &[u8],
            _mode: u32,
        ) -> Result<(), VaultError> {
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
            self.files.lock().unwrap().remove(path);
            Ok(())
        }

        async fn list_dir(&self, path: &Path) -> Result<Vec<String>, VaultError> {
            let files = self.files.lock().unwrap();
            Ok(files
                .keys()
                .filter_map(|p| {
                    if p.parent() == Some(path) {
                        p.file_name().map(|n| n.to_string_lossy().into_owned())
                    } else {
                        None
                    }
                })
                .collect())
        }

        fn platform(&self) -> Platform {
            self.platform
        }

        fn config_dir(&self) -> &Path {
            &self.config_dir
        }
    }

    fn new_backend(host: Arc<TestHost>) -> DpapiBackend {
        DpapiBackend::new(host, None)
    }

    // ── AC1: store is argv-safe — the secret only ever travels on stdin ───

    #[tokio::test]
    async fn store_passes_secret_on_stdin_not_argv() {
        let host = TestHost::new();
        let backend = new_backend(host.clone());
        const SENTINEL: &str = "argv-sentinel-should-never-appear-in-args";
        backend.store("sentinel-id", SENTINEL).await.unwrap();

        let calls = host.calls.lock().unwrap();
        // ensure_storage_dir doesn't shell out, so the only exec call here
        // is the encrypt script.
        let store_calls: Vec<_> = calls
            .iter()
            .filter(|c| c.args.iter().any(|a| a.contains("::Protect(")))
            .collect();
        assert_eq!(
            store_calls.len(),
            1,
            "store should issue exactly one Protect exec call"
        );
        let call = store_calls[0];
        assert_eq!(call.cmd, "powershell");
        assert!(
            call.args.iter().all(|a| !a.contains(SENTINEL)),
            "the secret must never appear in child process argv: {:?}",
            call.args
        );
        let expected_b64 = Base64::encode_string(SENTINEL.as_bytes());
        assert!(
            call.args.iter().all(|a| !a.contains(&expected_b64)),
            "the base64-encoded secret must never appear in argv either: {:?}",
            call.args
        );
        assert_eq!(
            call.stdin.as_deref(),
            Some(expected_b64.as_bytes()),
            "the secret must be delivered base64-encoded on stdin"
        );
    }

    #[tokio::test]
    async fn store_argv_sentinel_survives_full_round_trip() {
        let host = TestHost::new();
        let backend = new_backend(host.clone());
        const SENTINEL: &str = "super-secret-value-42";

        backend.store("rt-id", SENTINEL).await.unwrap();
        let retrieved = backend.retrieve("rt-id").await.unwrap();
        assert_eq!(retrieved, SENTINEL);
        backend.delete("rt-id").await.unwrap();

        let calls = host.calls.lock().unwrap();
        for call in calls.iter() {
            assert!(
                call.args.iter().all(|a| !a.contains(SENTINEL)),
                "the secret must never appear in child process argv at any step: {:?}",
                call.args
            );
        }
    }

    // ── AC2: byte-for-byte round trip of spaces/quotes/newlines/non-ASCII ──

    #[tokio::test]
    async fn round_trips_secret_with_spaces_quotes_and_embedded_newlines() {
        let host = TestHost::new();
        let backend = new_backend(host);
        let secret = "hello \"world\" 'quoted'\nmiddle line\r\nend";
        backend.store("spaces-quotes-id", secret).await.unwrap();
        let retrieved = backend.retrieve("spaces-quotes-id").await.unwrap();
        assert_eq!(retrieved, secret);
    }

    #[tokio::test]
    async fn round_trips_non_ascii_secret_byte_for_byte() {
        let host = TestHost::new();
        let backend = new_backend(host);
        let secret = "pässwörd-日本語-emoji-🔐-Ñoño";
        backend.store("non-ascii-id", secret).await.unwrap();
        let retrieved = backend.retrieve("non-ascii-id").await.unwrap();
        assert_eq!(retrieved, secret);
    }

    #[tokio::test]
    async fn round_trips_secret_with_leading_and_trailing_whitespace() {
        // The base64-over-stdout retrieve design (see module docs) preserves
        // leading/trailing whitespace too, unlike the TS backend's
        // `.trim()`-sensitive plain-text stdout channel.
        let host = TestHost::new();
        let backend = new_backend(host);
        let secret = "  leading and trailing spaces  \n";
        backend.store("whitespace-id", secret).await.unwrap();
        let retrieved = backend.retrieve("whitespace-id").await.unwrap();
        assert_eq!(retrieved, secret);
    }

    // ── AC3: entry-path scheme matches the TS backend byte-for-byte ───────

    #[test]
    fn entry_path_uses_hex_encoded_id_matching_ts_backend() {
        // packages/vaultkeeper/src/backend/dpapi-backend.ts: getEntryPath
        let host = TestHost::new();
        let backend = new_backend(host);
        let path = backend.entry_path("my-secret");
        let expected_hex = hex_encode(b"my-secret");
        assert_eq!(
            path.file_name().unwrap().to_string_lossy(),
            format!("{expected_hex}.enc")
        );
    }

    #[test]
    fn honors_backend_config_path_override() {
        // Regression parity with TS issue #60 (BackendConfig.path honored).
        let host = TestHost::new();
        let custom_dir = PathBuf::from("/custom/dpapi/dir");
        let backend = DpapiBackend::new(host, Some(custom_dir.clone()));
        assert_eq!(backend.storage_dir(), custom_dir);
    }

    #[test]
    fn defaults_to_config_dir_slash_dpapi() {
        let host = TestHost::new();
        let backend = new_backend(host.clone());
        assert_eq!(backend.storage_dir(), host.config_dir.join("dpapi"));
    }

    // ── AC4: missing entry and corrupted/truncated blob surface typed
    //         errors, never a partial/garbage secret ─────────────────────

    #[tokio::test]
    async fn retrieve_missing_entry_returns_secret_not_found() {
        let host = TestHost::new();
        let backend = new_backend(host);
        let err = backend.retrieve("nonexistent").await.unwrap_err();
        assert!(
            matches!(err, VaultError::SecretNotFound { .. }),
            "expected SecretNotFound, got {err:?}"
        );
    }

    #[tokio::test]
    async fn retrieve_corrupted_blob_returns_decryption_error_not_garbage() {
        let host = TestHost::new();
        let backend = new_backend(host.clone());
        let entry_path = backend.entry_path("corrupt-id");
        // Write bytes that don't carry the fake-DPAPI magic prefix, i.e. not
        // a valid Protect() output — simulates a corrupted/truncated blob.
        host.files
            .lock()
            .unwrap()
            .insert(entry_path, b"not-a-real-dpapi-blob".to_vec());

        let err = backend.retrieve("corrupt-id").await.unwrap_err();
        assert!(
            matches!(err, VaultError::Decryption { .. }),
            "expected Decryption, got {err:?}"
        );
    }

    #[tokio::test]
    async fn retrieve_truncated_blob_returns_decryption_error() {
        let host = TestHost::new();
        let backend = new_backend(host.clone());
        // Store a real entry, then truncate it to simulate a partial write.
        backend.store("trunc-id", "some-secret").await.unwrap();
        let entry_path = backend.entry_path("trunc-id");
        {
            let mut files = host.files.lock().unwrap();
            let bytes = files.get_mut(&entry_path).unwrap();
            bytes.truncate(FAKE_DPAPI_MAGIC.len() + 2);
        }

        let err = backend.retrieve("trunc-id").await.unwrap_err();
        assert!(
            matches!(err, VaultError::Decryption { .. }),
            "expected Decryption, got {err:?}"
        );
    }

    #[tokio::test]
    async fn delete_missing_returns_secret_not_found() {
        let host = TestHost::new();
        let backend = new_backend(host);
        let err = backend.delete("nonexistent").await.unwrap_err();
        assert!(
            matches!(err, VaultError::SecretNotFound { .. }),
            "expected SecretNotFound, got {err:?}"
        );
    }

    #[tokio::test]
    async fn store_failure_surfaces_typed_exec_error_not_panic() {
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
                    stderr: b"ProtectedData.Protect threw an exception".to_vec(),
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

        let host = Arc::new(FailingHost {
            inner: TestHost::new(),
        });
        let backend = DpapiBackend::new(host, None);
        let err = backend.store("id", "secret").await.unwrap_err();
        assert!(
            matches!(err, VaultError::Exec { ref command, .. } if command == "powershell"),
            "expected VaultError::Exec carrying the failing command, got {err:?}"
        );
    }

    // ── Additional coverage: store/retrieve/list/is_available/display ─────

    #[tokio::test]
    async fn store_and_retrieve_round_trip() {
        let host = TestHost::new();
        let backend = new_backend(host);
        backend.store("my-key", "my-secret").await.unwrap();
        let retrieved = backend.retrieve("my-key").await.unwrap();
        assert_eq!(retrieved, "my-secret");
    }

    #[tokio::test]
    async fn exists_returns_false_for_missing_and_true_for_present() {
        let host = TestHost::new();
        let backend = new_backend(host);
        assert!(!backend.exists("nonexistent").await.unwrap());
        backend.store("present-id", "value").await.unwrap();
        assert!(backend.exists("present-id").await.unwrap());
    }

    #[tokio::test]
    async fn list_returns_decoded_ids_for_stored_entries() {
        let host = TestHost::new();
        let backend = new_backend(host);
        backend.store("alpha", "val-a").await.unwrap();
        backend.store("beta", "val-b").await.unwrap();
        let mut ids = backend.list().await.unwrap();
        ids.sort();
        assert_eq!(ids, vec!["alpha", "beta"]);
    }

    #[tokio::test]
    async fn list_returns_empty_when_storage_dir_does_not_exist() {
        let host = TestHost::new();
        let backend = new_backend(host);
        assert_eq!(backend.list().await.unwrap(), Vec::<String>::new());
    }

    #[tokio::test]
    async fn is_available_false_on_non_windows_platform() {
        let host = Arc::new(TestHost {
            config_dir: PathBuf::from("/test/config"),
            files: Mutex::new(HashMap::new()),
            calls: Mutex::new(Vec::new()),
            platform: Platform::Darwin,
            version_unavailable: false,
        });
        let backend = new_backend(host);
        assert!(!backend.is_available().await);
    }

    #[tokio::test]
    async fn is_available_true_on_windows_when_powershell_responds() {
        let host = TestHost::new();
        let backend = new_backend(host);
        assert!(backend.is_available().await);
    }

    #[tokio::test]
    async fn is_available_false_when_powershell_not_installed() {
        let host = Arc::new(TestHost {
            config_dir: PathBuf::from("/test/config"),
            files: Mutex::new(HashMap::new()),
            calls: Mutex::new(Vec::new()),
            platform: Platform::Windows,
            version_unavailable: true,
        });
        let backend = new_backend(host);
        assert!(!backend.is_available().await);
    }

    #[test]
    fn backend_type_and_display_name() {
        let host = TestHost::new();
        let backend = new_backend(host);
        assert_eq!(backend.backend_type(), "dpapi");
        assert_eq!(backend.display_name(), "Windows DPAPI");
    }

    #[test]
    fn hex_round_trip() {
        let data = "hello-world";
        let encoded = hex_encode(data.as_bytes());
        let decoded = hex_decode(&encoded).unwrap();
        assert_eq!(decoded, data.as_bytes());
    }
}
