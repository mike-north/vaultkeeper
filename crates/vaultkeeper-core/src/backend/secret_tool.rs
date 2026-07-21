//! Linux Secret Service backend, driven via the `secret-tool(1)` CLI.
//!
//! Ports the TypeScript `SecretToolBackend`
//! (`packages/vaultkeeper/src/backend/secret-tool-backend.ts`) into
//! `vaultkeeper-core`, unchanged in wire behavior: same attribute/collection
//! schema, same four `secret-tool` verbs (`store`, `lookup`, `clear`,
//! `search`), same argv-safe stdin handoff for the secret value. Entries
//! written by either implementation are mutually readable because the
//! attribute schema below is byte-for-byte identical to the TS backend's.
//!
//! No filesystem persistence and no crypto in this backend — the Secret
//! Service daemon (GNOME Keyring, KWallet's Secret Service plugin, etc.) owns
//! storage; this is purely a [`HostPlatform::exec`] orchestration layer.

use crate::backend::types::{ExecOptions, HostPlatform, ListableBackend, Platform, SecretBackend};
use crate::errors::VaultError;
use std::sync::Arc;

/// Attribute key used to tag every vaultkeeper-managed Secret Service entry.
/// Must match the TS backend's `ATTRIBUTE_KEY` exactly.
const ATTRIBUTE_KEY: &str = "vaultkeeper-id";

/// Label prefix applied to entries created via `store`. Must match the TS
/// backend's `LABEL_PREFIX` exactly.
const LABEL_PREFIX: &str = "vaultkeeper: ";

/// Linux Secret Service (`secret-tool`) backend.
///
/// Only meaningfully available on Linux with `secret-tool` installed and a
/// running Secret Service (e.g. GNOME Keyring or KWallet with the Secret
/// Service plugin) reachable over D-Bus.
pub struct SecretToolBackend {
    host: Arc<dyn HostPlatform>,
}

impl SecretToolBackend {
    /// Create a new `SecretToolBackend` using the given host for subprocess
    /// orchestration.
    pub fn new(host: Arc<dyn HostPlatform>) -> Self {
        Self { host }
    }

    /// Parse `attribute.vaultkeeper-id = <id>` lines out of `secret-tool
    /// search` output — the same line-oriented parse the TS backend performs
    /// via its `attribute\.vaultkeeper-id = (.+)` regex.
    fn parse_search_ids(stdout: &str) -> Vec<String> {
        let prefix = format!("attribute.{ATTRIBUTE_KEY} = ");
        stdout
            .lines()
            .filter_map(|line| line.strip_prefix(prefix.as_str()))
            .map(|id| id.to_string())
            .collect()
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl SecretBackend for SecretToolBackend {
    fn backend_type(&self) -> &str {
        "secret-tool"
    }

    fn display_name(&self) -> &str {
        "Linux Secret Service (secret-tool)"
    }

    async fn is_available(&self) -> bool {
        if self.host.platform() != Platform::Linux {
            return false;
        }
        match self
            .host
            .exec("secret-tool", &["--version"], ExecOptions::default())
            .await
        {
            Ok(output) => output.exit_code == 0,
            Err(_) => false,
        }
    }

    async fn store(&self, id: &str, secret: &str) -> Result<(), VaultError> {
        let label = format!("{LABEL_PREFIX}{id}");
        let args = ["store", "--label", label.as_str(), ATTRIBUTE_KEY, id];
        let output = self
            .host
            .exec(
                "secret-tool",
                &args,
                ExecOptions {
                    stdin: Some(secret.as_bytes()),
                    ..Default::default()
                },
            )
            .await?;
        if output.exit_code != 0 {
            return Err(VaultError::Other(format!(
                "secret-tool store failed with exit code {}: {}",
                output.exit_code,
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        Ok(())
    }

    async fn retrieve(&self, id: &str) -> Result<String, VaultError> {
        let output = self
            .host
            .exec(
                "secret-tool",
                &["lookup", ATTRIBUTE_KEY, id],
                ExecOptions::default(),
            )
            .await?;
        let stdout = String::from_utf8(output.stdout).map_err(|e| {
            VaultError::Other(format!("secret-tool lookup returned non-UTF-8 output: {e}"))
        })?;
        if output.exit_code != 0 || stdout.trim().is_empty() {
            return Err(VaultError::SecretNotFound {
                message: format!("Secret not found in Secret Service: {id}"),
            });
        }
        Ok(stdout.trim().to_string())
    }

    async fn delete(&self, id: &str) -> Result<(), VaultError> {
        let output = self
            .host
            .exec(
                "secret-tool",
                &["clear", ATTRIBUTE_KEY, id],
                ExecOptions::default(),
            )
            .await?;
        if output.exit_code != 0 {
            return Err(VaultError::SecretNotFound {
                message: format!("Secret not found in Secret Service: {id}"),
            });
        }
        Ok(())
    }

    async fn exists(&self, id: &str) -> Result<bool, VaultError> {
        let output = self
            .host
            .exec(
                "secret-tool",
                &["lookup", ATTRIBUTE_KEY, id],
                ExecOptions::default(),
            )
            .await?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(output.exit_code == 0 && !stdout.trim().is_empty())
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl ListableBackend for SecretToolBackend {
    async fn list(&self) -> Result<Vec<String>, VaultError> {
        let output = self
            .host
            .exec(
                "secret-tool",
                &["search", ATTRIBUTE_KEY, ""],
                ExecOptions::default(),
            )
            .await?;
        if output.exit_code != 0 {
            return Ok(Vec::new());
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(Self::parse_search_ids(&stdout))
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

    /// Test double for `HostPlatform` that fakes a Secret Service store in
    /// memory, keyed by the `vaultkeeper-id` attribute value, and records
    /// every subprocess invocation for argv inspection.
    struct TestHost {
        config_dir: PathBuf,
        /// id -> (label, secret)
        entries: Mutex<std::collections::HashMap<String, (String, String)>>,
        calls: Mutex<Vec<RecordedExec>>,
        /// When true, `--version` reports secret-tool as unavailable.
        version_unavailable: bool,
        platform: Platform,
    }

    impl TestHost {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                config_dir: PathBuf::from("/test/config"),
                entries: Mutex::new(std::collections::HashMap::new()),
                calls: Mutex::new(Vec::new()),
                version_unavailable: false,
                platform: Platform::Linux,
            })
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
                Some("--version") => {
                    if self.version_unavailable {
                        return Ok(ExecOutput {
                            stdout: Vec::new(),
                            stderr: b"command not found".to_vec(),
                            exit_code: 127,
                        });
                    }
                    Ok(ExecOutput {
                        stdout: b"secret-tool 0.21".to_vec(),
                        stderr: Vec::new(),
                        exit_code: 0,
                    })
                }
                Some("store") => {
                    // ["store", "--label", label, ATTRIBUTE_KEY, id]
                    let label = args.get(2).expect("label arg").to_string();
                    let id = args.get(4).expect("id arg").to_string();
                    let secret = options
                        .stdin
                        .map(|b| String::from_utf8_lossy(b).to_string())
                        .unwrap_or_default();
                    self.entries.lock().unwrap().insert(id, (label, secret));
                    Ok(ExecOutput {
                        stdout: Vec::new(),
                        stderr: Vec::new(),
                        exit_code: 0,
                    })
                }
                Some("lookup") => {
                    // ["lookup", ATTRIBUTE_KEY, id]
                    let id = args.get(2).expect("id arg").to_string();
                    match self.entries.lock().unwrap().get(&id) {
                        Some((_, secret)) => Ok(ExecOutput {
                            stdout: format!("{secret}\n").into_bytes(),
                            stderr: Vec::new(),
                            exit_code: 0,
                        }),
                        None => Ok(ExecOutput {
                            stdout: Vec::new(),
                            stderr: b"No matching items found".to_vec(),
                            exit_code: 1,
                        }),
                    }
                }
                Some("clear") => {
                    // ["clear", ATTRIBUTE_KEY, id]
                    let id = args.get(2).expect("id arg").to_string();
                    let removed = self.entries.lock().unwrap().remove(&id).is_some();
                    Ok(ExecOutput {
                        stdout: Vec::new(),
                        stderr: if removed {
                            Vec::new()
                        } else {
                            b"No matching items found".to_vec()
                        },
                        exit_code: if removed { 0 } else { 1 },
                    })
                }
                Some("search") => {
                    let entries = self.entries.lock().unwrap();
                    let mut stdout = String::new();
                    for (id, (label, _)) in entries.iter() {
                        stdout.push_str(&format!(
                            "[/org/freedesktop/secrets/collection/login/{id}]\n"
                        ));
                        stdout.push_str(&format!("label = {label}\n"));
                        stdout.push_str("secret = \n");
                        stdout.push_str("schema: org.freedesktop.Secret.Generic\n");
                        stdout.push_str(&format!("attribute.{ATTRIBUTE_KEY} = {id}\n"));
                        stdout.push('\n');
                    }
                    Ok(ExecOutput {
                        stdout: stdout.into_bytes(),
                        stderr: Vec::new(),
                        exit_code: 0,
                    })
                }
                other => panic!("unexpected secret-tool invocation: {other:?}"),
            }
        }
        async fn read_file(&self, _path: &Path) -> Result<Vec<u8>, VaultError> {
            panic!("SecretToolBackend must not touch the filesystem")
        }
        async fn write_file(
            &self,
            _path: &Path,
            _content: &[u8],
            _mode: u32,
        ) -> Result<(), VaultError> {
            panic!("SecretToolBackend must not touch the filesystem")
        }
        async fn file_exists(&self, _path: &Path) -> Result<bool, VaultError> {
            panic!("SecretToolBackend must not touch the filesystem")
        }
        async fn delete_file(&self, _path: &Path) -> Result<(), VaultError> {
            panic!("SecretToolBackend must not touch the filesystem")
        }
        async fn list_dir(&self, _path: &Path) -> Result<Vec<String>, VaultError> {
            panic!("SecretToolBackend must not touch the filesystem")
        }
        fn platform(&self) -> Platform {
            self.platform
        }
        fn config_dir(&self) -> &Path {
            &self.config_dir
        }
    }

    // ── AC4: attribute schema parity with the TS backend ──────────────────

    #[test]
    fn attribute_key_matches_ts_backend() {
        // packages/vaultkeeper/src/backend/secret-tool-backend.ts: ATTRIBUTE_KEY
        assert_eq!(ATTRIBUTE_KEY, "vaultkeeper-id");
    }

    #[test]
    fn label_prefix_matches_ts_backend() {
        // packages/vaultkeeper/src/backend/secret-tool-backend.ts: LABEL_PREFIX
        assert_eq!(LABEL_PREFIX, "vaultkeeper: ");
    }

    #[tokio::test]
    async fn store_uses_attribute_key_and_label_prefix_in_argv() {
        let host = TestHost::new();
        let backend = SecretToolBackend::new(host.clone());
        backend.store("my-secret", "secret-value").await.unwrap();

        let calls = host.calls.lock().unwrap();
        let store_call = calls.iter().find(|c| c.cmd == "secret-tool").unwrap();
        assert_eq!(
            store_call.args,
            vec![
                "store",
                "--label",
                "vaultkeeper: my-secret",
                "vaultkeeper-id",
                "my-secret",
            ]
        );
    }

    // ── AC1: store is argv-safe — the secret only ever travels on stdin ───

    #[tokio::test]
    async fn store_passes_secret_on_stdin_not_argv() {
        let host = TestHost::new();
        let backend = SecretToolBackend::new(host.clone());
        const SENTINEL: &str = "argv-sentinel-should-never-appear-in-args";
        backend.store("sentinel-id", SENTINEL).await.unwrap();

        let calls = host.calls.lock().unwrap();
        assert_eq!(calls.len(), 1, "store should issue exactly one exec call");
        let call = &calls[0];
        assert!(
            call.args.iter().all(|a| !a.contains(SENTINEL)),
            "the secret must never appear in child process argv: {:?}",
            call.args
        );
        assert_eq!(
            call.stdin.as_deref(),
            Some(SENTINEL.as_bytes()),
            "the secret must be delivered on stdin"
        );
    }

    #[tokio::test]
    async fn store_argv_sentinel_survives_full_round_trip() {
        // Broader regression: run store -> retrieve -> delete and assert the
        // sentinel never leaked into argv at any step, not just store.
        let host = TestHost::new();
        let backend = SecretToolBackend::new(host.clone());
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
        let backend = SecretToolBackend::new(host.clone());
        // Newline is embedded (not leading/trailing) since `secret-tool
        // lookup` output is trimmed on both ends, matching the TS backend's
        // `.trim()` — a leading/trailing newline is not preserved by design,
        // matching the TS semantics this port must replicate faithfully.
        let secret = "hello \"world\" 'quoted'\nmiddle line\nend";
        backend.store("spaces-quotes-id", secret).await.unwrap();
        let retrieved = backend.retrieve("spaces-quotes-id").await.unwrap();
        assert_eq!(retrieved, secret);
    }

    #[tokio::test]
    async fn round_trips_non_ascii_secret_byte_for_byte() {
        let host = TestHost::new();
        let backend = SecretToolBackend::new(host.clone());
        let secret = "pässwörd-日本語-emoji-🔐-Ñoño";
        backend.store("non-ascii-id", secret).await.unwrap();
        let retrieved = backend.retrieve("non-ascii-id").await.unwrap();
        assert_eq!(retrieved, secret);
    }

    // ── AC3: not-found semantics for retrieve/delete never panic ──────────

    #[tokio::test]
    async fn retrieve_missing_returns_secret_not_found() {
        let host = TestHost::new();
        let backend = SecretToolBackend::new(host);
        let err = backend.retrieve("nonexistent").await.unwrap_err();
        assert!(
            matches!(err, VaultError::SecretNotFound { .. }),
            "expected SecretNotFound, got {err:?}"
        );
    }

    #[tokio::test]
    async fn delete_missing_returns_secret_not_found() {
        let host = TestHost::new();
        let backend = SecretToolBackend::new(host);
        let err = backend.delete("nonexistent").await.unwrap_err();
        assert!(
            matches!(err, VaultError::SecretNotFound { .. }),
            "expected SecretNotFound, got {err:?}"
        );
    }

    #[tokio::test]
    async fn exists_returns_false_for_missing_and_true_for_present() {
        let host = TestHost::new();
        let backend = SecretToolBackend::new(host);
        assert!(!backend.exists("nonexistent").await.unwrap());
        backend.store("present-id", "value").await.unwrap();
        assert!(backend.exists("present-id").await.unwrap());
    }

    // ── Additional coverage: store/list/is_available/display ──────────────

    #[tokio::test]
    async fn store_and_retrieve_round_trip() {
        let host = TestHost::new();
        let backend = SecretToolBackend::new(host);
        backend.store("my-key", "my-secret").await.unwrap();
        let retrieved = backend.retrieve("my-key").await.unwrap();
        assert_eq!(retrieved, "my-secret");
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
                    stderr: b"secret-tool: dbus connection failed".to_vec(),
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
        let err = SecretToolBackend::new(host)
            .store("id", "secret")
            .await
            .unwrap_err();
        assert!(
            matches!(err, VaultError::Other(_)),
            "expected a typed VaultError, got {err:?}"
        );
    }

    #[tokio::test]
    async fn list_parses_attribute_lines_from_search_output() {
        let host = TestHost::new();
        let backend = SecretToolBackend::new(host);
        backend.store("alpha", "val-a").await.unwrap();
        backend.store("beta", "val-b").await.unwrap();
        let mut ids = backend.list().await.unwrap();
        ids.sort();
        assert_eq!(ids, vec!["alpha", "beta"]);
    }

    #[test]
    fn parse_search_ids_matches_ts_backend_output_shape() {
        // Mirrors the fixture in
        // packages/vaultkeeper/test/unit/backend/secret-tool-backend.test.ts
        let stdout = [
            "[/org/freedesktop/secrets/collection/login/1]",
            "label = vaultkeeper: my-secret",
            "secret = ",
            "created = 2024-01-01 00:00:00",
            "modified = 2024-01-01 00:00:00",
            "schema: org.freedesktop.Secret.Generic",
            "attribute.vaultkeeper-id = my-secret",
            "",
            "[/org/freedesktop/secrets/collection/login/2]",
            "label = vaultkeeper: another-secret",
            "secret = ",
            "attribute.vaultkeeper-id = another-secret",
        ]
        .join("\n");

        let ids = SecretToolBackend::parse_search_ids(&stdout);
        assert_eq!(ids, vec!["my-secret", "another-secret"]);
    }

    #[tokio::test]
    async fn list_returns_empty_when_search_fails() {
        struct FailingSearchHost {
            inner: Arc<TestHost>,
        }

        #[async_trait::async_trait]
        impl HostPlatform for FailingSearchHost {
            async fn exec(
                &self,
                cmd: &str,
                args: &[&str],
                options: ExecOptions<'_>,
            ) -> Result<ExecOutput, VaultError> {
                if args.first().copied() == Some("search") {
                    return Ok(ExecOutput {
                        stdout: Vec::new(),
                        stderr: b"No matching items found".to_vec(),
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

        let host = Arc::new(FailingSearchHost {
            inner: TestHost::new(),
        });
        let backend = SecretToolBackend::new(host);
        assert_eq!(backend.list().await.unwrap(), Vec::<String>::new());
    }

    #[tokio::test]
    async fn is_available_false_on_non_linux_platform() {
        let host = Arc::new(TestHost {
            config_dir: PathBuf::from("/test/config"),
            entries: Mutex::new(std::collections::HashMap::new()),
            calls: Mutex::new(Vec::new()),
            version_unavailable: false,
            platform: Platform::Darwin,
        });
        let backend = SecretToolBackend::new(host);
        assert!(!backend.is_available().await);
    }

    #[tokio::test]
    async fn is_available_true_on_linux_when_secret_tool_responds() {
        let host = TestHost::new();
        let backend = SecretToolBackend::new(host);
        assert!(backend.is_available().await);
    }

    #[tokio::test]
    async fn is_available_false_when_secret_tool_not_installed() {
        let host = Arc::new(TestHost {
            config_dir: PathBuf::from("/test/config"),
            entries: Mutex::new(std::collections::HashMap::new()),
            calls: Mutex::new(Vec::new()),
            version_unavailable: true,
            platform: Platform::Linux,
        });
        let backend = SecretToolBackend::new(host);
        assert!(!backend.is_available().await);
    }

    #[test]
    fn backend_type_and_display_name() {
        let host = TestHost::new();
        let backend = SecretToolBackend::new(host);
        assert_eq!(backend.backend_type(), "secret-tool");
        assert_eq!(backend.display_name(), "Linux Secret Service (secret-tool)");
    }
}
