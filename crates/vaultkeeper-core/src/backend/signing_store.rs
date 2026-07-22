//! Encrypted persistence for `FileBackend`'s [`SigningBackend`](super::SigningBackend)
//! signing-key private material (issue #289).
//!
//! Signing private keys are a distinct resource from stored secrets — they
//! must never flow through [`super::SecretBackend::store`]/`retrieve`, never
//! land in `keys.enc` (the vault key-state envelope; see
//! `crate::keys::storage`), and never appear in a token's claims. Each
//! Ed25519 private key is instead sealed as its own AES-256-GCM envelope
//! under a `signing/` subdirectory of the host's config directory — a
//! separate namespace from both the `file/` secret-storage directory and
//! `keys.enc`.
//!
//! The seal key is HKDF-SHA256 derived from the same `.keys.wrap` material
//! [`crate::keys::storage`] uses to wrap vault key state, but under a
//! distinct HKDF `info` label ([`HKDF_INFO`]) — a separate cryptographic
//! namespace, not merely a separate directory. This is what lets a signing
//! key and a stored secret share the same caller-facing `id` without any
//! collision: they are sealed under unrelated derived keys and live under
//! unrelated directories.
//!
//! Mirrors [`super::file::FileBackend`]'s `aes-gcm` + `base64ct` envelope
//! discipline exactly: `iv:authTag:ciphertext` (each part base64), atomic
//! write-to-temp-then-rename via [`HostPlatform::rename_file`]. Kept
//! self-contained (its own `encrypt_gcm`/`decrypt_gcm`, mirroring
//! `crate::keys::storage`'s documented rationale) rather than reaching into
//! `file.rs`'s private helpers, which keeps this module's on-disk contract
//! independently reviewable.

use std::path::{Path, PathBuf};

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64ct::{Base64, Encoding};
use ed25519_dalek::SigningKey;
use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use super::file::hex_encode;
use crate::backend::HostPlatform;
use crate::errors::VaultError;
use crate::keys::storage::{KEY_WRAP_FILE, get_or_create_wrap_key};
use crate::signing::ed25519::{kid_for_verifying_key, sign as ed25519_sign};
use crate::types::{SigningAlgorithm, SigningPublicKey};

/// Subdirectory (of the host config dir) holding sealed signing-key private
/// material. Distinct from `file/` (secrets) and `keys.enc`/`.keys.wrap`
/// (vault key state).
const SIGNING_DIR: &str = "signing";
const GCM_IV_BYTES: usize = 12;
const GCM_KEY_BYTES: usize = 32;
const GCM_TAG_BYTES: usize = 16;

/// Distinct HKDF namespace label for the signing-key seal key. Any other
/// purpose that in the future also derives a key from `.keys.wrap` must use
/// a different label — this is what guarantees a signing key and a secret
/// (or any other derived-key consumer) sharing the same caller-facing `id`
/// never collide, since they are sealed under cryptographically unrelated
/// keys, not merely different directories.
const HKDF_INFO: &[u8] = b"vaultkeeper-core/backend/file/signing-key/v1";

fn signing_dir(host: &dyn HostPlatform) -> PathBuf {
    host.config_dir().join(SIGNING_DIR)
}

fn signing_key_path(host: &dyn HostPlatform, id: &str) -> PathBuf {
    let safe_id = hex_encode(id.as_bytes());
    signing_dir(host).join(format!("{safe_id}.enc"))
}

// ---------------------------------------------------------------------------
// AES-256-GCM envelope (iv:authTag:ciphertext, base64) — mirrors
// `backend::file`'s envelope byte-for-byte.
// ---------------------------------------------------------------------------

fn encrypt_gcm(key: &[u8], plaintext: &str) -> Result<String, VaultError> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| VaultError::Other(format!("Invalid signing seal key: {e}")))?;

    let mut iv = [0u8; GCM_IV_BYTES];
    getrandom::fill(&mut iv)
        .map_err(|e| VaultError::Other(format!("Failed to generate IV: {e}")))?;
    let nonce = Nonce::from_slice(&iv);

    let ciphertext_with_tag = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| VaultError::Other(format!("Encryption failed: {e}")))?;

    let tag_start = ciphertext_with_tag.len() - GCM_TAG_BYTES;
    let ciphertext = &ciphertext_with_tag[..tag_start];
    let auth_tag = &ciphertext_with_tag[tag_start..];

    Ok(format!(
        "{}:{}:{}",
        Base64::encode_string(&iv),
        Base64::encode_string(auth_tag),
        Base64::encode_string(ciphertext),
    ))
}

fn decrypt_gcm(key: &[u8], encoded: &str) -> Result<Zeroizing<String>, VaultError> {
    let parts: Vec<&str> = encoded.split(':').collect();
    if parts.len() != 3 {
        return Err(VaultError::Other(
            "Invalid encrypted signing-key file format: expected iv:authTag:ciphertext".to_string(),
        ));
    }

    let iv = Base64::decode_vec(parts[0])
        .map_err(|e| VaultError::Other(format!("Invalid IV base64: {e}")))?;
    if iv.len() != GCM_IV_BYTES {
        return Err(VaultError::Other(format!(
            "AES-GCM IV must be {GCM_IV_BYTES} bytes, got {}",
            iv.len()
        )));
    }
    let auth_tag = Base64::decode_vec(parts[1])
        .map_err(|e| VaultError::Other(format!("Invalid auth tag base64: {e}")))?;
    if auth_tag.len() != GCM_TAG_BYTES {
        return Err(VaultError::Other(format!(
            "AES-GCM auth tag must be {GCM_TAG_BYTES} bytes, got {}",
            auth_tag.len()
        )));
    }
    let ciphertext = Base64::decode_vec(parts[2])
        .map_err(|e| VaultError::Other(format!("Invalid ciphertext base64: {e}")))?;

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| VaultError::Other(format!("Invalid signing seal key: {e}")))?;
    let nonce = Nonce::from_slice(&iv);

    let mut combined = ciphertext;
    combined.extend_from_slice(&auth_tag);

    let mut plaintext = cipher
        .decrypt(nonce, combined.as_slice())
        .map_err(|e| VaultError::Other(format!("Decryption failed: {e}")))?;

    match String::from_utf8(plaintext) {
        Ok(s) => Ok(Zeroizing::new(s)),
        Err(e) => {
            // The decrypted bytes are private key material (or, on a
            // corrupt/tampered envelope, whatever GCM happened to decrypt to
            // — still sensitive enough to treat the same way) even though
            // they failed UTF-8 validation. `FromUtf8Error` owns those bytes;
            // recover and zeroize them before the error is dropped rather
            // than leaving them to a plain `Vec<u8>` drop.
            let message = format!("Decrypted data is not valid UTF-8: {}", e.utf8_error());
            plaintext = e.into_bytes();
            plaintext.zeroize();
            Err(VaultError::Other(message))
        }
    }
}

/// Derive the signing-key seal key: HKDF-SHA256 over the shared `.keys.wrap`
/// material (read-or-create, exactly like `crate::keys::storage`), expanded
/// under [`HKDF_INFO`] — a namespace no other derivation in this codebase
/// uses.
async fn get_signing_seal_key(host: &dyn HostPlatform) -> Result<Vec<u8>, VaultError> {
    let wrap_path = host.config_dir().join(KEY_WRAP_FILE);
    let mut wrap_key = get_or_create_wrap_key(host, &wrap_path).await?;

    let hk = Hkdf::<Sha256>::new(None, &wrap_key);
    wrap_key.zeroize();

    let mut seal_key = vec![0u8; GCM_KEY_BYTES];
    // `expand` only fails when the requested output length exceeds HKDF's
    // 255*HashLen limit (8160 bytes for SHA-256); a fixed 32-byte request
    // can never hit that, so this is unreachable in practice but still
    // surfaced as a typed error rather than unwrapped, matching this
    // module's "never panic on bad input" contract.
    hk.expand(HKDF_INFO, &mut seal_key)
        .map_err(|e| VaultError::Other(format!("HKDF expand failed: {e}")))?;
    Ok(seal_key)
}

/// Atomic write-to-temp-then-rename, mirroring `keys::storage::save_key_state`.
async fn write_atomic(
    host: &dyn HostPlatform,
    dest: &Path,
    content: &[u8],
) -> Result<(), VaultError> {
    let mut suffix = [0u8; 4];
    getrandom::fill(&mut suffix)
        .map_err(|e| VaultError::Other(format!("Failed to generate temp suffix: {e}")))?;
    let suffix_hex: String = suffix.iter().map(|b| format!("{b:02x}")).collect();
    let file_name = dest
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("signing-key");
    let tmp_path = dest.with_file_name(format!("{file_name}.{suffix_hex}.tmp"));

    host.write_file(&tmp_path, content, 0o600).await?;
    host.rename_file(&tmp_path, dest).await
}

/// Load and decrypt the PKCS#8 private key for `id`, or
/// [`VaultError::SigningKeyNotFound`] when no signing key exists under `id`.
async fn load_signing_key(host: &dyn HostPlatform, id: &str) -> Result<SigningKey, VaultError> {
    let path = signing_key_path(host, id);

    // Same "definitive read failure vs. disambiguating exists-probe" pattern
    // as `FileBackend::retrieve`: only a confirmed-missing entry becomes
    // `SigningKeyNotFound`; any other read failure (e.g. permissions)
    // propagates unchanged.
    let data = match host.read_file(&path).await {
        Ok(data) => data,
        Err(read_err) => {
            return match host.file_exists(&path).await {
                Ok(false) => Err(VaultError::SigningKeyNotFound {
                    message: format!("Signing key not found: {id}"),
                    id: id.to_string(),
                }),
                Ok(true) | Err(_) => Err(read_err),
            };
        }
    };

    let envelope = String::from_utf8(data).map_err(|e| VaultError::Decryption {
        message: format!("Signing key file is not valid UTF-8: {e}"),
        path: path.display().to_string(),
    })?;

    let mut seal_key = get_signing_seal_key(host).await?;
    let pem = decrypt_gcm(&seal_key, &envelope);
    seal_key.zeroize();
    let pem: Zeroizing<String> = pem.map_err(|e| VaultError::Decryption {
        message: format!("Failed to decrypt signing key: {e}"),
        path: path.display().to_string(),
    })?;

    SigningKey::from_pkcs8_pem(&pem).map_err(|_| VaultError::InvalidKeyMaterial {
        message: format!(
            "The stored signing key for \"{id}\" is not valid private key material \
             (it may be corrupt or tampered)."
        ),
    })
}

/// Enroll a new Ed25519 signing keypair under `id`.
///
/// # Errors
/// [`VaultError::SigningKeyAlreadyExists`] if a signing key already exists
/// under `id`; [`VaultError::InvalidAlgorithm`] if `algorithm` is not
/// `EdDSA` (the sole algorithm this backend supports today).
pub(crate) async fn generate_signing_key(
    host: &dyn HostPlatform,
    id: &str,
    algorithm: SigningAlgorithm,
) -> Result<(), VaultError> {
    // `SigningAlgorithm` currently has exactly one variant (`EdDsa`); this
    // match is exhaustive today and, if a second algorithm is ever added,
    // will fail to compile until this backend explicitly decides whether it
    // supports it — the correct place to add the `InvalidAlgorithm` branch
    // rather than a runtime default that could silently mis-handle it.
    match algorithm {
        SigningAlgorithm::EdDsa => {}
    }

    let path = signing_key_path(host, id);
    match host.file_exists(&path).await {
        Ok(true) => {
            return Err(VaultError::SigningKeyAlreadyExists {
                message: format!("Signing key already exists: {id}"),
                id: id.to_string(),
            });
        }
        Ok(false) => {}
        Err(e) => return Err(e),
    }

    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed)
        .map_err(|e| VaultError::Other(format!("Failed to generate signing key: {e}")))?;
    let signing_key = SigningKey::from_bytes(&seed);
    seed.zeroize();

    let pem = signing_key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| VaultError::Other(format!("Failed to encode signing key: {e}")))?;

    let mut seal_key = get_signing_seal_key(host).await?;
    let envelope = encrypt_gcm(&seal_key, &pem);
    seal_key.zeroize();
    let envelope = envelope?;

    write_atomic(host, &path, envelope.as_bytes()).await
}

/// Return the public half of the signing key stored under `id`.
///
/// # Errors
/// [`VaultError::SigningKeyNotFound`] if no signing key exists under `id`.
pub(crate) async fn get_public_key(
    host: &dyn HostPlatform,
    id: &str,
) -> Result<SigningPublicKey, VaultError> {
    let signing_key = load_signing_key(host, id).await?;
    let verifying_key = signing_key.verifying_key();

    let public_key_pem = verifying_key
        .to_public_key_pem(LineEnding::LF)
        .map_err(|e| VaultError::Other(format!("Failed to encode signing public key: {e}")))?;
    let kid = kid_for_verifying_key(&verifying_key);

    Ok(SigningPublicKey {
        public_key_pem,
        algorithm: SigningAlgorithm::EdDsa,
        kid,
    })
}

/// Sign `data` with the private key stored under `id`. The private key never
/// leaves this module — only the resulting signature bytes are returned.
///
/// # Errors
/// [`VaultError::SigningKeyNotFound`] if no signing key exists under `id`.
pub(crate) async fn sign_with_key(
    host: &dyn HostPlatform,
    id: &str,
    data: &[u8],
) -> Result<Vec<u8>, VaultError> {
    let signing_key = load_signing_key(host, id).await?;
    Ok(ed25519_sign(&signing_key, data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{ExecOptions, ExecOutput, Platform};
    use std::collections::{HashMap, HashSet};
    use std::sync::Mutex;

    struct TestHost {
        files: Mutex<HashMap<PathBuf, Vec<u8>>>,
        config_dir: PathBuf,
        deny_write: Mutex<HashSet<PathBuf>>,
        /// Deny every write whose parent directory equals this path,
        /// regardless of filename — used to fail an atomic write's
        /// unpredictable-suffix temp file without needing to guess the
        /// random suffix `write_atomic` generates.
        deny_write_under: Mutex<Option<PathBuf>>,
    }

    impl TestHost {
        fn new() -> Self {
            Self {
                files: Mutex::new(HashMap::new()),
                config_dir: PathBuf::from("/test/config"),
                deny_write: Mutex::new(HashSet::new()),
                deny_write_under: Mutex::new(None),
            }
        }
    }

    #[async_trait::async_trait]
    impl HostPlatform for TestHost {
        async fn exec(
            &self,
            _cmd: &str,
            _args: &[&str],
            _options: ExecOptions<'_>,
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
            if self.deny_write.lock().unwrap().contains(path)
                || self.deny_write_under.lock().unwrap().as_deref() == path.parent()
            {
                return Err(VaultError::Filesystem {
                    message: format!("Permission denied writing {}", path.display()),
                    path: path.display().to_string(),
                    permission: "write".to_string(),
                    code: None,
                });
            }
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
        async fn rename_file(&self, from: &Path, to: &Path) -> Result<(), VaultError> {
            let data = self
                .files
                .lock()
                .unwrap()
                .remove(from)
                .ok_or_else(|| VaultError::Other(format!("Not found: {}", from.display())))?;
            self.files.lock().unwrap().insert(to.to_path_buf(), data);
            Ok(())
        }
        async fn list_dir(&self, path: &Path) -> Result<Vec<String>, VaultError> {
            let files = self.files.lock().unwrap();
            let prefix = path.to_path_buf();
            Ok(files
                .keys()
                .filter_map(|k| {
                    if k.parent() == Some(&prefix) {
                        k.file_name().and_then(|n| n.to_str()).map(String::from)
                    } else {
                        None
                    }
                })
                .collect())
        }
        fn platform(&self) -> Platform {
            Platform::Linux
        }
        fn config_dir(&self) -> &Path {
            &self.config_dir
        }
    }

    // -----------------------------------------------------------------
    // AC1 — sign_with_key round-trips through the public key; wrong/absent
    // signing-key id returns a typed error, not a panic.
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn sign_with_key_produces_a_signature_verifiable_against_the_public_key() {
        let host = TestHost::new();
        generate_signing_key(&host, "my-key", SigningAlgorithm::EdDsa)
            .await
            .unwrap();

        let public_key = get_public_key(&host, "my-key").await.unwrap();
        let message = b"vaultkeeper issue #289";
        let signature = sign_with_key(&host, "my-key", message).await.unwrap();

        let verifying_key =
            crate::signing::ed25519::parse_public_key_pem(&public_key.public_key_pem).unwrap();
        assert!(crate::signing::ed25519::verify(
            &verifying_key,
            message,
            &signature
        ));
        assert_eq!(public_key.algorithm, SigningAlgorithm::EdDsa);
    }

    #[tokio::test]
    async fn sign_with_key_absent_id_returns_typed_error_not_panic() {
        let host = TestHost::new();
        let err = sign_with_key(&host, "no-such-key", b"data")
            .await
            .unwrap_err();
        assert!(matches!(err, VaultError::SigningKeyNotFound { id, .. } if id == "no-such-key"));
    }

    #[tokio::test]
    async fn get_public_key_absent_id_returns_typed_error() {
        let host = TestHost::new();
        let err = get_public_key(&host, "ghost").await.unwrap_err();
        assert!(matches!(err, VaultError::SigningKeyNotFound { .. }));
    }

    #[tokio::test]
    async fn generate_signing_key_rejects_duplicate_id() {
        let host = TestHost::new();
        generate_signing_key(&host, "dup", SigningAlgorithm::EdDsa)
            .await
            .unwrap();
        let err = generate_signing_key(&host, "dup", SigningAlgorithm::EdDsa)
            .await
            .unwrap_err();
        assert!(matches!(err, VaultError::SigningKeyAlreadyExists { id, .. } if id == "dup"));
    }

    // -----------------------------------------------------------------
    // AC2 — the private key is stored only under signing/, never in
    // keys.enc, never retrievable via SecretBackend::retrieve, never in a
    // token claim (the return types here structurally guarantee the latter:
    // sign_with_key returns Vec<u8> signature bytes, get_public_key returns
    // only the public half).
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn private_key_lives_only_under_signing_dir_not_keys_enc() {
        let host = TestHost::new();
        generate_signing_key(&host, "secret-key-name", SigningAlgorithm::EdDsa)
            .await
            .unwrap();

        let files = host.files.lock().unwrap();
        // Exactly two files were written: the shared `.keys.wrap` (created
        // on first HKDF derivation) and the sealed signing-key entry under
        // `signing/`. Neither `keys.enc` nor anything under `file/` exists.
        let paths: Vec<&PathBuf> = files.keys().collect();
        assert!(
            paths
                .iter()
                .all(|p| !p.to_string_lossy().contains("keys.enc")),
            "signing-key generation must never touch keys.enc: {paths:?}"
        );
        assert!(
            paths.iter().any(|p| p
                .parent()
                .is_some_and(|parent| parent.ends_with(SIGNING_DIR))),
            "expected an entry under signing/: {paths:?}"
        );
    }

    #[tokio::test]
    async fn private_key_material_absent_from_the_sealed_entry_and_pem_only_reachable_via_load() {
        let host = TestHost::new();
        generate_signing_key(&host, "leak-check", SigningAlgorithm::EdDsa)
            .await
            .unwrap();

        // The raw on-disk bytes are the GCM envelope, not the PEM/DER key
        // material — encrypted, not merely encoded.
        let path = signing_key_path(&host, "leak-check");
        let raw = host.read_file(&path).await.unwrap();
        let raw = String::from_utf8(raw).unwrap();
        assert!(!raw.contains("PRIVATE KEY"));
        assert_eq!(raw.split(':').count(), 3);
    }

    // -----------------------------------------------------------------
    // AC3 — HKDF-derived seal key is namespaced separately from the secret
    // path; a signing key and a stored secret with the same name coexist.
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn signing_seal_key_is_hkdf_derived_and_distinct_from_the_raw_wrap_key() {
        let host = TestHost::new();
        let wrap_path = host.config_dir().join(KEY_WRAP_FILE);
        let wrap_key = get_or_create_wrap_key(&host, &wrap_path).await.unwrap();
        let seal_key = get_signing_seal_key(&host).await.unwrap();

        assert_eq!(seal_key.len(), GCM_KEY_BYTES);
        assert_ne!(
            seal_key, wrap_key,
            "the HKDF-derived seal key must not equal the raw .keys.wrap bytes"
        );

        // Deterministic: deriving again from the same wrap material yields
        // the same seal key (HKDF is deterministic given the same IKM/info).
        let seal_key_again = get_signing_seal_key(&host).await.unwrap();
        assert_eq!(seal_key, seal_key_again);
    }

    #[tokio::test]
    async fn signing_key_and_secret_with_the_same_name_coexist_without_collision() {
        use crate::backend::{FileBackend, SecretBackend};
        use std::sync::Arc;

        let host = Arc::new(TestHost::new());
        let backend = FileBackend::new(host.clone());

        // Same caller-facing name used for both a stored secret and a
        // signing key.
        backend
            .store("shared-name", "the-secret-value")
            .await
            .unwrap();
        generate_signing_key(host.as_ref(), "shared-name", SigningAlgorithm::EdDsa)
            .await
            .unwrap();

        // Both are independently readable/usable, unaffected by the other.
        let secret = backend.retrieve("shared-name").await.unwrap();
        assert_eq!(secret, "the-secret-value");

        let signature = sign_with_key(host.as_ref(), "shared-name", b"msg")
            .await
            .unwrap();
        let public_key = get_public_key(host.as_ref(), "shared-name").await.unwrap();
        let verifying_key =
            crate::signing::ed25519::parse_public_key_pem(&public_key.public_key_pem).unwrap();
        assert!(crate::signing::ed25519::verify(
            &verifying_key,
            b"msg",
            &signature
        ));

        // Deleting the stored secret under the shared name must not touch
        // the signing key sealed under a wholly separate `signing/`
        // directory and HKDF namespace — it must still load and sign
        // exactly as before.
        backend.delete("shared-name").await.unwrap();
        assert!(!backend.exists("shared-name").await.unwrap());

        let signature_after_delete = sign_with_key(host.as_ref(), "shared-name", b"msg")
            .await
            .unwrap();
        let public_key_after_delete = get_public_key(host.as_ref(), "shared-name").await.unwrap();
        assert_eq!(
            public_key_after_delete.public_key_pem, public_key.public_key_pem,
            "the signing key must be unaffected by deleting the coexisting secret"
        );
        assert!(crate::signing::ed25519::verify(
            &verifying_key,
            b"msg",
            &signature_after_delete
        ));
    }

    // -----------------------------------------------------------------
    // AC4 — atomic writes: an interrupted write never leaves a partial
    // signing/ file readable as a key.
    // -----------------------------------------------------------------

    /// Structural guarantee: `write_atomic` only ever populates the temp
    /// path via `write_file`, and only ever populates `dest` via
    /// `rename_file`. So a write failure on the temp step can never leave a
    /// partial/garbage entry at `dest` — `dest` is either fully absent or
    /// (after a completed rename) fully the finished envelope. This test
    /// forces that failure directly (denying the exact temp path
    /// `write_atomic` will use) and asserts `dest` was never touched, and
    /// that the signing-key API surfaces the failure to read it back as
    /// `SigningKeyNotFound`, not a garbage key.
    #[tokio::test]
    async fn interrupted_write_leaves_no_partial_signing_file_readable_as_a_key() {
        let host = TestHost::new();
        let final_path = signing_key_path(&host, "interrupted");
        assert!(!host.file_exists(&final_path).await.unwrap());

        // Deny every write under signing/ (the temp file's random suffix is
        // unpredictable, so intercept by directory rather than exact path).
        *host.deny_write_under.lock().unwrap() = final_path.parent().map(Path::to_path_buf);
        let err = write_atomic(&host, &final_path, b"envelope-bytes")
            .await
            .unwrap_err();
        assert!(matches!(err, VaultError::Filesystem { .. }));

        assert!(!host.file_exists(&final_path).await.unwrap());
        let err = load_signing_key(&host, "interrupted").await.unwrap_err();
        assert!(matches!(err, VaultError::SigningKeyNotFound { .. }));
    }

    /// A *successful* atomic write leaves no leftover `*.tmp` file behind —
    /// the temp path is consumed by the rename, not merely copied.
    #[tokio::test]
    async fn successful_write_leaves_no_leftover_temp_file() {
        let host = TestHost::new();
        generate_signing_key(&host, "clean-write", SigningAlgorithm::EdDsa)
            .await
            .unwrap();

        let files = host.files.lock().unwrap();
        assert!(
            files.keys().all(|p| !p.to_string_lossy().ends_with(".tmp")),
            "no temp file should survive a successful atomic write: {:?}",
            files.keys().collect::<Vec<_>>()
        );
    }

    // -----------------------------------------------------------------
    // AC5 — tampering with a sealed signing/ file is detected by GCM
    // authentication and surfaces a typed error, never a garbage key.
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn tampered_sealed_file_is_detected_not_a_garbage_key() {
        let host = TestHost::new();
        generate_signing_key(&host, "tamper-me", SigningAlgorithm::EdDsa)
            .await
            .unwrap();

        let path = signing_key_path(&host, "tamper-me");
        let envelope = String::from_utf8(host.read_file(&path).await.unwrap()).unwrap();
        let parts: Vec<&str> = envelope.split(':').collect();
        let mut ct = Base64::decode_vec(parts[2]).unwrap();
        if !ct.is_empty() {
            ct[0] ^= 0xff;
        }
        let tampered = format!("{}:{}:{}", parts[0], parts[1], Base64::encode_string(&ct));
        host.write_file(&path, tampered.as_bytes(), 0o600)
            .await
            .unwrap();

        let err = get_public_key(&host, "tamper-me").await.unwrap_err();
        assert!(
            matches!(err, VaultError::Decryption { .. }),
            "expected VaultError::Decryption, got {err:?}"
        );

        let err = sign_with_key(&host, "tamper-me", b"data")
            .await
            .unwrap_err();
        assert!(matches!(err, VaultError::Decryption { .. }));
    }

    #[tokio::test]
    async fn garbage_bytes_in_place_of_a_sealed_file_returns_typed_error_not_panic() {
        let host = TestHost::new();
        let path = signing_key_path(&host, "garbage");
        host.write_file(&path, b"not-an-envelope-at-all", 0o600)
            .await
            .unwrap();

        let err = get_public_key(&host, "garbage").await.unwrap_err();
        assert!(matches!(err, VaultError::Decryption { .. }));
    }

    // -----------------------------------------------------------------
    // FileBackend is the first production SigningBackend. The golden-vector
    // tests in `tests/unit_tests.rs::signing` only ever exercise
    // `create_detached_jws`/`verify_detached_jws` against an in-memory test
    // double (`FixtureSigningBackend`), which never touches this module. The
    // fixture private key has no seam to import into `FileBackend`'s sealed
    // `signing/` storage without adding public API solely for this test, so
    // this instead proves the real backend end-to-end: a freshly generated
    // key, signed and verified through the same `crate::signing` module the
    // golden vectors exercise, using only the backend's own
    // `get_public_key` output — never a key reached into directly.
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn file_backend_signing_key_round_trips_through_create_and_verify_detached_jws() {
        use crate::backend::{FileBackend, SigningBackend};
        use crate::signing::{create_detached_jws, verify_detached_jws};
        use crate::types::VerifyRequest;
        use std::sync::Arc;

        let host = Arc::new(TestHost::new());
        let backend = FileBackend::new(host);
        backend
            .generate_signing_key("real-backend-key", SigningAlgorithm::EdDsa)
            .await
            .unwrap();

        let public_key = backend.get_public_key("real-backend-key").await.unwrap();
        let payload = b"vaultkeeper issue #289 real-backend round-trip coverage";

        let jws = create_detached_jws(&backend, &public_key.kid, "real-backend-key", payload)
            .await
            .unwrap();

        let verified = verify_detached_jws(&VerifyRequest {
            payload: payload.to_vec(),
            jws: jws.clone(),
            public_key: public_key.public_key_pem.clone(),
        })
        .unwrap();
        assert!(
            verified,
            "a JWS signed by the real FileBackend must verify against its own public key"
        );

        // A tampered payload must fail verification — proves this is a real
        // signature check, not a JWS that verifies unconditionally.
        let tampered = verify_detached_jws(&VerifyRequest {
            payload: b"a different payload entirely".to_vec(),
            jws,
            public_key: public_key.public_key_pem,
        })
        .unwrap();
        assert!(!tampered);
    }
}
