//! Encrypted file fallback backend.
//!
//! Stores secrets encrypted with AES-256-GCM. Each secret is stored as an
//! individual encrypted file under `<config_dir>/file/`. A randomly generated
//! 32-byte key stored in a protected file is used for encryption.
//!
//! Encrypted file format (all parts base64-encoded, colon-separated):
//!   `<iv>:<authTag>:<ciphertext>`

use crate::backend::types::{HostPlatform, ListableBackend, Platform, SecretBackend};
use crate::errors::VaultError;
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64ct::{Base64, Encoding};
use std::fmt::Write;
use std::path::PathBuf;
use std::sync::Arc;

const KEY_FILE: &str = ".key";
const GCM_IV_BYTES: usize = 12;
const GCM_KEY_BYTES: usize = 32;

/// Encrypted file fallback backend.
///
/// Available on all platforms. Stores secrets as AES-256-GCM encrypted files.
/// Not as secure as OS-native keystores, but provides a portable fallback.
pub struct FileBackend {
    host: Arc<dyn HostPlatform>,
}

impl FileBackend {
    /// Create a new FileBackend using the given host for I/O.
    pub fn new(host: Arc<dyn HostPlatform>) -> Self {
        Self { host }
    }

    fn storage_dir(&self) -> PathBuf {
        self.host.config_dir().join("file")
    }

    fn entry_path(&self, id: &str) -> PathBuf {
        let safe_id = hex_encode(id.as_bytes());
        self.storage_dir().join(format!("{safe_id}.enc"))
    }

    async fn ensure_storage_dir(&self) -> Result<(), VaultError> {
        let dir = self.storage_dir();
        // Create by writing a marker file, or just ensure the dir exists via host
        // We rely on the host's write_file creating parent dirs or the CLI creating it.
        // For simplicity, try to read a sentinel; if it fails, the dir doesn't exist.
        // The native host's write_file should handle missing parent dirs.
        let _ = self.host.file_exists(&dir).await;
        Ok(())
    }

    async fn get_or_create_key(&self) -> Result<Vec<u8>, VaultError> {
        let key_path = self.storage_dir().join(KEY_FILE);

        match self.host.read_file(&key_path).await {
            Ok(data) if data.len() == GCM_KEY_BYTES => Ok(data),
            Ok(data) => Err(VaultError::Other(format!(
                "Key file has wrong length: expected {GCM_KEY_BYTES}, got {}",
                data.len()
            ))),
            Err(read_err) => {
                // Only create a new key if the key file does not exist.
                // Transient read failures (permissions, IO errors) should be surfaced.
                match self.host.file_exists(&key_path).await {
                    Ok(false) => {
                        // File doesn't exist — generate a new key
                        let mut key = vec![0u8; GCM_KEY_BYTES];
                        getrandom::fill(&mut key)
                            .map_err(|e| VaultError::Other(format!("Failed to generate key: {e}")))?;
                        self.host
                            .write_file(&key_path, &key, 0o600)
                            .await?;
                        Ok(key)
                    }
                    Ok(true) => {
                        // File exists but couldn't be read — surface the original error
                        Err(read_err)
                    }
                    Err(exists_err) => Err(exists_err),
                }
            }
        }
    }
}

fn encrypt_gcm(key: &[u8], plaintext: &str) -> Result<String, VaultError> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| VaultError::Other(format!("Invalid key: {e}")))?;

    let mut iv = [0u8; GCM_IV_BYTES];
    getrandom::fill(&mut iv)
        .map_err(|e| VaultError::Other(format!("Failed to generate IV: {e}")))?;
    let nonce = Nonce::from_slice(&iv);

    let ciphertext_with_tag = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| VaultError::Other(format!("Encryption failed: {e}")))?;

    // aes-gcm appends the 16-byte auth tag to the ciphertext
    let tag_start = ciphertext_with_tag.len() - 16;
    let ciphertext = &ciphertext_with_tag[..tag_start];
    let auth_tag = &ciphertext_with_tag[tag_start..];

    Ok(format!(
        "{}:{}:{}",
        Base64::encode_string(&iv),
        Base64::encode_string(auth_tag),
        Base64::encode_string(ciphertext),
    ))
}

fn decrypt_gcm(key: &[u8], encoded: &str) -> Result<String, VaultError> {
    let parts: Vec<&str> = encoded.split(':').collect();
    if parts.len() != 3 {
        return Err(VaultError::Other(
            "Invalid encrypted file format: expected iv:authTag:ciphertext".to_string(),
        ));
    }

    let iv = Base64::decode_vec(parts[0])
        .map_err(|e| VaultError::Other(format!("Invalid IV base64: {e}")))?;
    if iv.len() != GCM_IV_BYTES {
        return Err(VaultError::Other(format!(
            "AES-GCM IV must be {} bytes, got {}",
            GCM_IV_BYTES,
            iv.len()
        )));
    }
    let auth_tag = Base64::decode_vec(parts[1])
        .map_err(|e| VaultError::Other(format!("Invalid auth tag base64: {e}")))?;
    if auth_tag.len() != 16 {
        return Err(VaultError::Other(format!(
            "AES-GCM auth tag must be 16 bytes, got {}",
            auth_tag.len()
        )));
    }
    let ciphertext = Base64::decode_vec(parts[2])
        .map_err(|e| VaultError::Other(format!("Invalid ciphertext base64: {e}")))?;

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| VaultError::Other(format!("Invalid key: {e}")))?;
    let nonce = Nonce::from_slice(&iv);

    // Reconstruct the ciphertext+tag format that aes-gcm expects
    let mut combined = ciphertext;
    combined.extend_from_slice(&auth_tag);

    let plaintext = cipher
        .decrypt(nonce, combined.as_slice())
        .map_err(|e| VaultError::Other(format!("Decryption failed: {e}")))?;

    String::from_utf8(plaintext)
        .map_err(|e| VaultError::Other(format!("Decrypted data is not valid UTF-8: {e}")))
}

/// Hex-encode bytes (used for safe filenames).
fn hex_encode(data: &[u8]) -> String {
    let mut hex = String::with_capacity(data.len() * 2);
    for byte in data {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// Hex-decode a string back to bytes.
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

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl SecretBackend for FileBackend {
    fn backend_type(&self) -> &str {
        "file"
    }

    fn display_name(&self) -> &str {
        "Encrypted File Store"
    }

    async fn is_available(&self) -> bool {
        self.ensure_storage_dir().await.is_ok()
    }

    async fn store(&self, id: &str, secret: &str) -> Result<(), VaultError> {
        self.ensure_storage_dir().await?;
        let key = self.get_or_create_key().await?;
        let encrypted = encrypt_gcm(&key, secret)?;
        let entry_path = self.entry_path(id);
        self.host
            .write_file(&entry_path, encrypted.as_bytes(), 0o600)
            .await
    }

    async fn retrieve(&self, id: &str) -> Result<String, VaultError> {
        let entry_path = self.entry_path(id);
        let data = self.host.read_file(&entry_path).await.map_err(|_| {
            VaultError::SecretNotFound {
                message: format!("Secret not found in file store: {id}"),
            }
        })?;

        let encoded = String::from_utf8(data)
            .map_err(|e| VaultError::Other(format!("Encrypted file is not valid UTF-8: {e}")))?;

        let key = self.get_or_create_key().await?;
        decrypt_gcm(&key, &encoded)
    }

    async fn delete(&self, id: &str) -> Result<(), VaultError> {
        let entry_path = self.entry_path(id);
        match self.host.file_exists(&entry_path).await {
            Ok(true) => {
                let path_str = entry_path.to_string_lossy();
                // Use runtime platform detection (not compile-time cfg!) so
                // WASM hosts report the correct platform at runtime.
                let (cmd, args): (&str, Vec<String>) = match self.host.platform() {
                    Platform::Windows => (
                        "cmd",
                        vec!["/c".to_string(), "del".to_string(), "/q".to_string(), path_str.to_string()],
                    ),
                    _ => (
                        "rm",
                        vec!["-f".to_string(), path_str.to_string()],
                    ),
                };
                let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
                let output = self.host
                    .exec(cmd, &arg_refs, None)
                    .await
                    .map_err(|e| {
                        VaultError::Other(format!("Failed to delete secret file: {e}"))
                    })?;
                if output.exit_code != 0 {
                    return Err(VaultError::Other(format!(
                        "Delete command exited with code {} for {}",
                        output.exit_code, path_str
                    )));
                }
                Ok(())
            }
            _ => Err(VaultError::SecretNotFound {
                message: format!("Secret not found in file store: {id}"),
            }),
        }
    }

    async fn exists(&self, id: &str) -> Result<bool, VaultError> {
        let entry_path = self.entry_path(id);
        self.host.file_exists(&entry_path).await
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl ListableBackend for FileBackend {
    async fn list(&self) -> Result<Vec<String>, VaultError> {
        let storage_dir = self.storage_dir();
        let dir_str = storage_dir.to_string_lossy().to_string();
        // Use runtime platform detection for the list command
        let (cmd, args): (&str, Vec<String>) = match self.host.platform() {
            Platform::Windows => (
                "cmd",
                vec!["/c".to_string(), "dir".to_string(), "/b".to_string(), dir_str],
            ),
            _ => ("ls", vec![dir_str]),
        };
        let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let output = match self.host.exec(cmd, &arg_refs, None).await {
            Ok(o) if o.exit_code == 0 => o,
            _ => return Ok(Vec::new()),
        };

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut names = Vec::new();
        for line in stdout.lines() {
            let filename = line.trim();
            if let Some(hex_name) = filename.strip_suffix(".enc")
                && let Ok(bytes) = hex_decode(hex_name)
                && let Ok(name) = String::from_utf8(bytes)
            {
                names.push(name);
            }
        }
        Ok(names)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn encrypt_decrypt_round_trip() {
        let mut key = [0u8; 32];
        getrandom::fill(&mut key).unwrap();
        let encrypted = encrypt_gcm(&key, "hello secret").unwrap();
        let decrypted = decrypt_gcm(&key, &encrypted).unwrap();
        assert_eq!(decrypted, "hello secret");
    }

    #[test]
    fn decrypt_with_wrong_key_fails() {
        let mut key1 = [0u8; 32];
        let mut key2 = [0u8; 32];
        getrandom::fill(&mut key1).unwrap();
        getrandom::fill(&mut key2).unwrap();
        let encrypted = encrypt_gcm(&key1, "secret").unwrap();
        assert!(decrypt_gcm(&key2, &encrypted).is_err());
    }

    #[test]
    fn decrypt_invalid_format_fails() {
        let key = [0u8; 32];
        assert!(decrypt_gcm(&key, "not:enough").is_err());
        assert!(decrypt_gcm(&key, "single").is_err());
    }

    #[test]
    fn decrypt_rejects_wrong_iv_length() {
        let key = [0u8; 32];
        // IV too short (base64 of 4 bytes instead of 12)
        let short_iv = Base64::encode_string(&[0u8; 4]);
        let tag = Base64::encode_string(&[0u8; 16]);
        let ct = Base64::encode_string(b"data");
        let encoded = format!("{short_iv}:{tag}:{ct}");
        let err = decrypt_gcm(&key, &encoded).unwrap_err();
        assert!(err.to_string().contains("IV must be"));
    }

    #[test]
    fn decrypt_rejects_wrong_tag_length() {
        let key = [0u8; 32];
        // Tag too short (8 bytes instead of 16)
        let iv = Base64::encode_string(&[0u8; GCM_IV_BYTES]);
        let short_tag = Base64::encode_string(&[0u8; 8]);
        let ct = Base64::encode_string(b"data");
        let encoded = format!("{iv}:{short_tag}:{ct}");
        let err = decrypt_gcm(&key, &encoded).unwrap_err();
        assert!(err.to_string().contains("auth tag must be 16 bytes"));
    }

    #[test]
    fn hex_round_trip() {
        let data = b"hello-world";
        let encoded = hex_encode(data);
        let decoded = hex_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn hex_encode_matches_expected() {
        assert_eq!(hex_encode(b"abc"), "616263");
    }

    #[tokio::test]
    async fn file_backend_store_and_retrieve() {
        use crate::backend::{ExecOutput, Platform};
        use std::collections::HashMap;
        use std::sync::Mutex;

        struct TestHost {
            files: Mutex<HashMap<PathBuf, Vec<u8>>>,
            config_dir: PathBuf,
        }

        #[async_trait::async_trait]
        impl HostPlatform for TestHost {
            async fn exec(
                &self,
                _cmd: &str,
                _args: &[&str],
                _stdin: Option<&[u8]>,
            ) -> Result<ExecOutput, VaultError> {
                Ok(ExecOutput {
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                    exit_code: 0,
                })
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
            fn platform(&self) -> Platform {
                Platform::Linux
            }
            fn config_dir(&self) -> &Path {
                &self.config_dir
            }
        }

        let host = Arc::new(TestHost {
            files: Mutex::new(HashMap::new()),
            config_dir: PathBuf::from("/test/config"),
        });

        let backend = FileBackend::new(host);
        backend.store("my-key", "my-secret").await.unwrap();

        assert!(backend.exists("my-key").await.unwrap());
        assert!(!backend.exists("other-key").await.unwrap());

        let retrieved = backend.retrieve("my-key").await.unwrap();
        assert_eq!(retrieved, "my-secret");
    }

    #[tokio::test]
    async fn file_backend_retrieve_missing_returns_error() {
        use crate::backend::{ExecOutput, Platform};
        use std::collections::HashMap;
        use std::sync::Mutex;

        struct TestHost {
            files: Mutex<HashMap<PathBuf, Vec<u8>>>,
            config_dir: PathBuf,
        }

        #[async_trait::async_trait]
        impl HostPlatform for TestHost {
            async fn exec(
                &self,
                _cmd: &str,
                _args: &[&str],
                _stdin: Option<&[u8]>,
            ) -> Result<ExecOutput, VaultError> {
                Ok(ExecOutput {
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                    exit_code: 0,
                })
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
            fn platform(&self) -> Platform {
                Platform::Linux
            }
            fn config_dir(&self) -> &Path {
                &self.config_dir
            }
        }

        let host = Arc::new(TestHost {
            files: Mutex::new(HashMap::new()),
            config_dir: PathBuf::from("/test/config"),
        });

        let backend = FileBackend::new(host);
        let result = backend.retrieve("nonexistent").await;
        assert!(result.is_err());
    }
}
