//! YubiKey backend, driven via the `ykman(1)` CLI over [`HostPlatform::exec`].
//!
//! Ports the TypeScript `YubikeyBackend`
//! (`packages/vaultkeeper/src/backend/yubikey-backend.ts`) into
//! `vaultkeeper-core`, preserving its on-disk contract exactly: same
//! `<hex(id)>.enc` entry-path scheme, same `metadata.json` `{ entries: {...}
//! } }` shape (keyed by id; the TS backend's `list()` only ever reads the
//! object's keys, so the stored value is opaque bookkeeping and does not
//! need to match byte-for-byte across implementations), and the same
//! versioned `1:<iv>:<authTag>:<ciphertext>` AES-256-GCM envelope with a key
//! derived via HKDF-SHA-256 from the YubiKey's HMAC-SHA1 challenge-response
//! (slot 2), binding the derived key to the secret's `id` via the HKDF
//! `info` field. Entries written by either implementation are mutually
//! readable.
//!
//! # argv safety
//!
//! The secret itself never crosses a child-process boundary: `store` and
//! `retrieve` perform the challenge-response over `ykman otp calculate 2
//! <hex-challenge>` (only an id-derived hex value in argv) and do all
//! encryption/decryption in-process. No `ykman` invocation ever receives the
//! secret as an argument.
//!
//! # Legacy AES-256-CBC detection (not decryption)
//!
//! Before the GCM migration (TS commit 87ed778, "Fix YubiKey backend:
//! replace AES-256-CBC with AES-256-GCM"), the TS backend shelled out to
//! `openssl enc -aes-256-cbc -pbkdf2 -pass stdin`, producing raw OpenSSL
//! `Salted__...` output with no version prefix. The TS backend has never
//! implemented CBC *decryption* — a non-versioned blob is detected and
//! surfaced as a typed error asking the operator to delete and re-store,
//! because OpenSSL's `-pbkdf2` key-derivation defaults (iteration count,
//! digest) are version-dependent and were never pinned by the old code, so a
//! reimplemented decrypt could silently produce the wrong plaintext for a
//! blob written by a different OpenSSL version rather than failing cleanly.
//! This port matches that behavior exactly (see issue #293 discussion).

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64ct::{Base64, Encoding};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::backend::file::hex_encode;
use crate::backend::types::{
    BackendCapabilities, ExecOptions, HostPlatform, ListableBackend, PresenceCapableBackend,
    SecretBackend,
};
use crate::errors::VaultError;

const YKMAN_INSTALL_URL: &str = "https://developers.yubico.com/yubikey-manager/";
const STORAGE_SUBDIR: &str = "yubikey";
const METADATA_FILE: &str = "metadata.json";
const DEVICE_TIMEOUT_MS: u64 = 5000;

/// AES-256-GCM constants.
const GCM_IV_BYTES: usize = 12;
const GCM_KEY_BYTES: usize = 32;
const GCM_TAG_BYTES: usize = 16;

/// Version prefix written at the start of every encrypted file. Must match
/// the TS backend's `FORMAT_VERSION` exactly.
const FORMAT_VERSION: &str = "1";

/// Expected byte length of a YubiKey HMAC-SHA1 response (20 bytes = 40 hex
/// chars). Must match the TS backend's `HMAC_RESPONSE_HEX_LENGTH` exactly.
const HMAC_RESPONSE_HEX_LENGTH: usize = 40;

/// On-disk shape of `metadata.json`, matching the TS backend's
/// `YubikeyMetadata` interface exactly (`{ entries: Record<string, string> }`).
/// A `BTreeMap` (rather than `HashMap`) keeps this port's own writes
/// deterministically ordered; it has no bearing on reading TS-written files,
/// since JSON object key order is irrelevant to `serde_json`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct YubikeyMetadata {
    #[serde(default)]
    entries: BTreeMap<String, String>,
}

/// YubiKey backend via `ykman` CLI.
///
/// Requires `ykman` to be installed and a YubiKey to be connected. Secrets
/// are stored as individually AES-256-GCM-encrypted files under
/// `<config_dir>/yubikey/`. The encryption key is derived from the
/// YubiKey's HMAC-SHA1 challenge-response (slot 2) via HKDF-SHA-256, binding
/// each secret to its `id`.
pub struct YubikeyBackend {
    host: Arc<dyn HostPlatform>,
    /// Whether the configured challenge-response slot enforces a touch for
    /// every operation. Sourced from configuration (mirroring the TS
    /// backend's `requireTouch` constructor parameter), never hardcoded by
    /// backend type — see [`YubikeyBackend::get_capabilities`].
    require_touch: bool,
}

impl YubikeyBackend {
    /// Create a new `YubikeyBackend` using the given host for subprocess and
    /// filesystem I/O.
    ///
    /// `require_touch` mirrors the TS backend's `requireTouch` constructor
    /// parameter: whether the configured challenge-response slot enforces a
    /// touch-per-operation policy (verify with `ykman otp info`). Defaults
    /// are the caller's responsibility, matching every other constructor in
    /// this module (no built-in default is assumed here).
    pub fn new(host: Arc<dyn HostPlatform>, require_touch: bool) -> Self {
        Self {
            host,
            require_touch,
        }
    }

    fn storage_dir(&self) -> PathBuf {
        self.host.config_dir().join(STORAGE_SUBDIR)
    }

    fn entry_path(&self, id: &str) -> PathBuf {
        let safe_id = hex_encode(id.as_bytes());
        self.storage_dir().join(format!("{safe_id}.enc"))
    }

    fn metadata_path(&self) -> PathBuf {
        self.storage_dir().join(METADATA_FILE)
    }

    /// Load `metadata.json`, matching the TS backend's `loadMetadata`: any
    /// failure to read or parse (missing file, corrupt JSON, wrong shape)
    /// is swallowed and treated as an empty store rather than propagated —
    /// `list()` on a fresh/corrupt store must report no entries, not error.
    async fn load_metadata(&self) -> YubikeyMetadata {
        match self.host.read_file(&self.metadata_path()).await {
            Ok(data) => serde_json::from_slice(&data).unwrap_or_default(),
            Err(_) => YubikeyMetadata::default(),
        }
    }

    async fn save_metadata(&self, metadata: &YubikeyMetadata) -> Result<(), VaultError> {
        let json = serde_json::to_string_pretty(metadata)
            .map_err(|e| VaultError::Other(format!("Failed to serialize metadata: {e}")))?;
        self.host
            .write_file(&self.metadata_path(), json.as_bytes(), 0o600)
            .await
    }

    /// Perform the YubiKey HMAC-SHA1 challenge-response for `id` and return
    /// the raw hex response string. The challenge is `hex("vaultkeeper:{id}")`
    /// — only this id-derived hex value ever reaches `ykman`'s argv, never
    /// the secret itself.
    ///
    /// The response is key material (it is the sole input to [`derive_key`])
    /// and is returned wrapped in [`Zeroizing`] so it is scrubbed from memory
    /// as soon as its last owner (the caller) drops it, mirroring
    /// `signing_store`'s handling of derived key material end-to-end.
    async fn challenge_response(&self, id: &str) -> Result<Zeroizing<String>, VaultError> {
        let challenge = hex_encode(format!("vaultkeeper:{id}").as_bytes());
        let output = self
            .host
            .exec(
                "ykman",
                &["otp", "calculate", "2", &challenge],
                ExecOptions::default(),
            )
            .await?;
        if output.exit_code != 0 {
            return Err(VaultError::Exec {
                message: format!(
                    "YubiKey challenge-response failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                ),
                command: "ykman".to_string(),
            });
        }
        Ok(Zeroizing::new(
            String::from_utf8_lossy(&output.stdout).trim().to_string(),
        ))
    }

    async fn require_device(&self) -> Result<(), VaultError> {
        if self.is_available_inner().await {
            return Ok(());
        }
        let has_ykman = matches!(
            self.host
                .exec("ykman", &["--version"], ExecOptions::default())
                .await,
            Ok(output) if output.exit_code == 0
        );
        if !has_ykman {
            return Err(VaultError::PluginNotFound {
                message: "ykman is not installed".to_string(),
                plugin: "ykman".to_string(),
                install_url: YKMAN_INSTALL_URL.to_string(),
            });
        }
        Err(VaultError::DeviceNotPresent {
            message: "No YubiKey device detected".to_string(),
            timeout_ms: DEVICE_TIMEOUT_MS,
        })
    }

    async fn is_available_inner(&self) -> bool {
        match self
            .host
            .exec("ykman", &["--version"], ExecOptions::default())
            .await
        {
            Ok(output) if output.exit_code == 0 => {}
            _ => return false,
        }
        match self
            .host
            .exec("ykman", &["list"], ExecOptions::default())
            .await
        {
            Ok(output) => {
                output.exit_code == 0 && !String::from_utf8_lossy(&output.stdout).trim().is_empty()
            }
            Err(_) => false,
        }
    }
}

// ---------------------------------------------------------------------------
// Key derivation (HKDF-SHA-256 over the YubiKey HMAC-SHA1 challenge-response)
// ---------------------------------------------------------------------------

/// Derive a 256-bit AES key from the YubiKey HMAC-SHA1 response using
/// HKDF-SHA-256, matching the TS backend's `deriveKey` exactly.
///
/// The HMAC-SHA1 response is 20 bytes — too short and too biased to use
/// directly as an AES-256 key. HKDF expands it to exactly 32 bytes while
/// binding the key to the secret `id` via the `info` field
/// (`vaultkeeper-yubikey:<id>`), so a key derived for one id can never
/// decrypt an entry stored under another.
///
/// Returns [`VaultError::Setup`] (naming the `ykman` dependency, mirroring
/// the TS backend's typed `SetupError`) if `hmac_response` is not exactly
/// [`HMAC_RESPONSE_HEX_LENGTH`] hex characters — a malformed or truncated
/// `ykman` response.
///
/// Both the raw IKM (the hex-decoded HMAC response) and the returned AES key
/// are key material and are scrubbed accordingly: the IKM is held in a
/// [`Zeroizing`] buffer for its whole lifetime, and the returned key is
/// [`Zeroizing`] so it is scrubbed as soon as its last owner drops it —
/// mirroring `signing_store`'s handling of derived key material.
fn derive_key(hmac_response: &str, id: &str) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let trimmed = hmac_response.trim();
    let is_valid_hex =
        trimmed.len() == HMAC_RESPONSE_HEX_LENGTH && trimmed.bytes().all(|b| b.is_ascii_hexdigit());
    if !is_valid_hex {
        return Err(VaultError::Setup {
            message: format!(
                "Invalid YubiKey HMAC response: expected exactly {HMAC_RESPONSE_HEX_LENGTH} hex \
                 characters (20 bytes), got {} characters",
                trimmed.len()
            ),
            dependency: "ykman".to_string(),
        });
    }

    let ikm = Zeroizing::new(hex_decode(trimmed)?);
    let info = format!("vaultkeeper-yubikey:{id}");
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut key = Zeroizing::new(vec![0u8; GCM_KEY_BYTES]);
    // A fixed 32-byte request can never exceed HKDF's 255*HashLen output
    // limit, so this is unreachable in practice but still surfaced as a
    // typed error rather than unwrapped.
    hk.expand(info.as_bytes(), &mut key)
        .map_err(|e| VaultError::Other(format!("HKDF expand failed: {e}")))?;
    Ok(key)
}

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

// ---------------------------------------------------------------------------
// Versioned AES-256-GCM envelope: `1:<iv>:<authTag>:<ciphertext>` (each
// binary part base64), matching the TS backend's `encryptGcm`/`decryptGcm`.
// ---------------------------------------------------------------------------

fn encrypt_gcm_versioned(key: &[u8], plaintext: &str) -> Result<String, VaultError> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| VaultError::Other(format!("Invalid key: {e}")))?;

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
        "{FORMAT_VERSION}:{}:{}:{}",
        Base64::encode_string(&iv),
        Base64::encode_string(auth_tag),
        Base64::encode_string(ciphertext),
    ))
}

/// Decrypt a versioned GCM blob produced by [`encrypt_gcm_versioned`].
///
/// Version detection distinguishes three cases, matching the TS backend's
/// `decryptGcm` exactly:
/// - First segment is exactly [`FORMAT_VERSION`] → current format, proceed.
/// - First segment is a different (but well-formed) unsigned integer → an
///   unsupported *future* version this build cannot decode.
/// - First segment is not a plain non-negative integer at all (e.g. OpenSSL's
///   `Salted__` header, or any other non-numeric/malformed prefix) → legacy
///   or corrupt data; see the module-level docs on why this port only
///   *detects* — never decrypts — the pre-GCM AES-256-CBC format.
///
/// All failure branches return [`VaultError::Decryption`] carrying `path`,
/// mirroring the TS backend's typed `DecryptionError`.
///
/// The decrypted plaintext is the secret itself, so it is returned wrapped in
/// [`Zeroizing`] — mirroring `signing_store::decrypt_gcm`'s handling of its
/// own decrypted private-key material, including the same treatment of the
/// non-UTF-8 failure path: `String::from_utf8`'s error owns the raw decrypted
/// bytes, so they are recovered from it and explicitly zeroized before the
/// error is returned, rather than left to a plain `Vec<u8>` drop.
fn decrypt_gcm_versioned(
    key: &[u8],
    encoded: &str,
    path: &str,
) -> Result<Zeroizing<String>, VaultError> {
    let legacy_err = || VaultError::Decryption {
        message: "Encrypted file uses a legacy format (AES-256-CBC). Delete the secret and \
                  re-store it to migrate to AES-256-GCM."
            .to_string(),
        path: path.to_string(),
    };

    let parts: Vec<&str> = encoded.split(':').collect();
    let version_segment = parts.first().copied().unwrap_or("");

    // A "numeric version prefix" is a non-empty run of ASCII digits with no
    // leading zero anomalies (e.g. "01" would round-trip differently from
    // its parsed value) — matches the TS backend's
    // `String(parseInt(v, 10)) === v` check.
    let is_numeric_version = !version_segment.is_empty()
        && version_segment.bytes().all(|b| b.is_ascii_digit())
        && version_segment
            .parse::<u64>()
            .is_ok_and(|parsed| parsed.to_string() == version_segment);

    if !is_numeric_version {
        return Err(legacy_err());
    }

    if version_segment != FORMAT_VERSION {
        return Err(VaultError::Decryption {
            message: format!(
                "Unsupported encrypted file version: {version_segment}. This vaultkeeper \
                 build only supports version {FORMAT_VERSION}. Upgrade vaultkeeper to read \
                 this secret."
            ),
            path: path.to_string(),
        });
    }

    if parts.len() != 4 {
        return Err(VaultError::Decryption {
            message: format!(
                "Invalid encrypted file format: expected {FORMAT_VERSION}:iv:authTag:ciphertext"
            ),
            path: path.to_string(),
        });
    }

    let iv = Base64::decode_vec(parts[1]).map_err(|e| VaultError::Decryption {
        message: format!("Invalid IV base64: {e}"),
        path: path.to_string(),
    })?;
    if iv.len() != GCM_IV_BYTES {
        return Err(VaultError::Decryption {
            message: format!("AES-GCM IV must be {GCM_IV_BYTES} bytes, got {}", iv.len()),
            path: path.to_string(),
        });
    }
    let auth_tag = Base64::decode_vec(parts[2]).map_err(|e| VaultError::Decryption {
        message: format!("Invalid auth tag base64: {e}"),
        path: path.to_string(),
    })?;
    if auth_tag.len() != GCM_TAG_BYTES {
        return Err(VaultError::Decryption {
            message: format!(
                "AES-GCM auth tag must be {GCM_TAG_BYTES} bytes, got {}",
                auth_tag.len()
            ),
            path: path.to_string(),
        });
    }
    let ciphertext = Base64::decode_vec(parts[3]).map_err(|e| VaultError::Decryption {
        message: format!("Invalid ciphertext base64: {e}"),
        path: path.to_string(),
    })?;

    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| VaultError::Decryption {
        message: format!("Invalid key: {e}"),
        path: path.to_string(),
    })?;
    let nonce = Nonce::from_slice(&iv);

    let mut combined = ciphertext;
    combined.extend_from_slice(&auth_tag);

    let plaintext =
        cipher
            .decrypt(nonce, combined.as_slice())
            .map_err(|e| VaultError::Decryption {
                message: format!(
                    "GCM authentication failed — ciphertext may be tampered or corrupt: {e}"
                ),
                path: path.to_string(),
            })?;

    match String::from_utf8(plaintext) {
        Ok(s) => Ok(Zeroizing::new(s)),
        Err(e) => {
            // The decrypted bytes are the secret (or, on a corrupt/tampered
            // envelope, whatever GCM happened to decrypt to — still
            // sensitive enough to treat the same way) even though they
            // failed UTF-8 validation. `FromUtf8Error` owns those bytes;
            // recover and zeroize them before the error is dropped rather
            // than leaving them to a plain `Vec<u8>` drop.
            let message = format!("Decrypted data is not valid UTF-8: {}", e.utf8_error());
            let mut plaintext = e.into_bytes();
            plaintext.zeroize();
            Err(VaultError::Decryption {
                message,
                path: path.to_string(),
            })
        }
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl SecretBackend for YubikeyBackend {
    fn backend_type(&self) -> &str {
        "yubikey"
    }

    fn display_name(&self) -> &str {
        "YubiKey"
    }

    async fn is_available(&self) -> bool {
        self.is_available_inner().await
    }

    async fn store(&self, id: &str, secret: &str) -> Result<(), VaultError> {
        self.require_device().await?;

        let hmac_response = self.challenge_response(id).await?;
        let key = derive_key(&hmac_response, id)?;
        let encrypted = encrypt_gcm_versioned(&key, secret)?;

        let entry_path = self.entry_path(id);
        // `write_file` creates every missing ancestor directory owner-only
        // (`0o700`) before writing (see `NativeHostPlatform::write_file`) —
        // this is what satisfies "storage dir created with 0o700 via the
        // host directory-creation path" without a `.keep` sentinel.
        self.host
            .write_file(&entry_path, encrypted.as_bytes(), 0o600)
            .await?;

        let mut metadata = self.load_metadata().await;
        metadata
            .entries
            .insert(id.to_string(), entry_path.display().to_string());
        self.save_metadata(&metadata).await
    }

    async fn retrieve(&self, id: &str) -> Result<String, VaultError> {
        self.require_device().await?;

        let entry_path = self.entry_path(id);

        // Act first, then disambiguate on failure — never probe existence
        // before acting. A `file_exists` check followed by a separate
        // `read_file` call is a TOCTOU race: the entry can be deleted (or
        // fail to exist for unrelated reasons) between the two calls, and a
        // caller relying on the up-front probe would misreport a genuine
        // filesystem error as `SecretNotFound` or vice versa. Only a
        // definitive read failure is disambiguated afterward, mirroring
        // `FileBackend::retrieve` and `signing_store::load_signing_key`
        // exactly: a confirmed-missing entry becomes `SecretNotFound`; any
        // other read failure (e.g. EACCES/EPERM) propagates unchanged.
        let data = match self.host.read_file(&entry_path).await {
            Ok(data) => data,
            Err(read_err) => {
                return match self.host.file_exists(&entry_path).await {
                    Ok(false) => Err(VaultError::SecretNotFound {
                        message: format!("Secret not found in YubiKey store: {id}"),
                    }),
                    Ok(true) | Err(_) => Err(read_err),
                };
            }
        };
        // The stored entry is UTF-8 text by design for the current versioned
        // format, but a legacy pre-GCM entry is raw OpenSSL binary output —
        // lossily decode (never hard-fail here) so a legacy/corrupt blob
        // still reaches `decrypt_gcm_versioned`'s version-detection branch
        // and surfaces the intended typed error, matching the TS backend's
        // `fs.readFile(path, 'utf8')` (which never throws on invalid UTF-8).
        let encoded = String::from_utf8_lossy(&data).into_owned();

        let hmac_response = self.challenge_response(id).await?;
        let key = derive_key(&hmac_response, id)?;

        let plaintext = decrypt_gcm_versioned(&key, &encoded, &entry_path.display().to_string())?;
        // The `SecretBackend` trait returns a plain `String` — this is the
        // one point where the secret must leave `Zeroizing` custody and be
        // handed to the caller, who becomes responsible for it from here.
        // `Zeroizing<String>` exposes no `into_inner` (it would let a caller
        // silently opt out of the zero-on-drop guarantee), so the contained
        // value is cloned out; the original `Zeroizing` copy is still
        // scrubbed when it drops at the end of this scope.
        Ok((*plaintext).clone())
    }

    async fn delete(&self, id: &str) -> Result<(), VaultError> {
        self.require_device().await?;

        let entry_path = self.entry_path(id);

        // Same act-first-then-disambiguate shape as `retrieve` above: never
        // probe existence before acting, only afterward to distinguish a
        // genuine "already gone" from a real filesystem error.
        match self.host.delete_file(&entry_path).await {
            Ok(()) => {}
            Err(delete_err) => {
                return match self.host.file_exists(&entry_path).await {
                    Ok(false) => Err(VaultError::SecretNotFound {
                        message: format!("Secret not found in YubiKey store: {id}"),
                    }),
                    Ok(true) | Err(_) => Err(delete_err),
                };
            }
        }

        let mut metadata = self.load_metadata().await;
        metadata.entries.remove(id);
        self.save_metadata(&metadata).await
    }

    async fn exists(&self, id: &str) -> Result<bool, VaultError> {
        self.host.file_exists(&self.entry_path(id)).await
    }

    fn as_presence_capable(&self) -> Option<&dyn PresenceCapableBackend> {
        Some(self)
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl ListableBackend for YubikeyBackend {
    async fn list(&self) -> Result<Vec<String>, VaultError> {
        let metadata = self.load_metadata().await;
        Ok(metadata.entries.into_keys().collect())
    }
}

/// `presence_per_use` is `true` only when the configured slot enforces a
/// touch-per-operation policy (`require_touch`), matching the TS backend's
/// `getCapabilities` exactly: the answer always comes from the
/// operator-declared configuration, never derived from the backend type
/// alone.
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl PresenceCapableBackend for YubikeyBackend {
    async fn get_capabilities(&self) -> Result<BackendCapabilities, VaultError> {
        Ok(BackendCapabilities {
            presence_per_use: self.require_touch,
            presence_enforced_operations: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{ExecOutput, Platform};
    use std::collections::{HashMap, HashSet};
    use std::path::Path;
    use std::sync::Mutex;

    /// Records every `exec` invocation (command, args, stdin) so tests can
    /// assert on exactly what was shelled out — in particular, the
    /// argv-sentinel assertion for AC1.
    #[derive(Debug, Clone)]
    struct RecordedExec {
        args: Vec<String>,
    }

    /// Test double for `HostPlatform` that fakes both `ykman` subprocess
    /// behavior and the on-disk store, so tests run without hardware or a
    /// real filesystem.
    struct TestHost {
        config_dir: PathBuf,
        files: Mutex<HashMap<PathBuf, Vec<u8>>>,
        calls: Mutex<Vec<RecordedExec>>,
        /// Fixed HMAC-SHA1 challenge-response hex string every `otp
        /// calculate` invocation answers with, regardless of the challenge —
        /// mirrors the TS test suite's `FAKE_HMAC_RESPONSE`.
        hmac_response: Mutex<String>,
        device_available: bool,
        ykman_installed: bool,
        /// Paths that must fail `read_file`/`delete_file` with a
        /// `VaultError::Filesystem` (simulating e.g. EACCES/EPERM) even
        /// though the entry exists — lets tests distinguish the act-first
        /// disambiguation path from the "genuinely missing" path.
        deny_read: Mutex<HashSet<PathBuf>>,
        deny_delete: Mutex<HashSet<PathBuf>>,
    }

    const FAKE_HMAC_RESPONSE: &str = "deadbeefcafe01234567deadbeefcafe01234567";

    impl TestHost {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                config_dir: PathBuf::from("/test/config"),
                files: Mutex::new(HashMap::new()),
                calls: Mutex::new(Vec::new()),
                hmac_response: Mutex::new(FAKE_HMAC_RESPONSE.to_string()),
                device_available: true,
                ykman_installed: true,
                deny_read: Mutex::new(HashSet::new()),
                deny_delete: Mutex::new(HashSet::new()),
            })
        }

        fn unavailable_device() -> Arc<Self> {
            Arc::new(Self {
                config_dir: PathBuf::from("/test/config"),
                files: Mutex::new(HashMap::new()),
                calls: Mutex::new(Vec::new()),
                hmac_response: Mutex::new(FAKE_HMAC_RESPONSE.to_string()),
                device_available: false,
                ykman_installed: true,
                deny_read: Mutex::new(HashSet::new()),
                deny_delete: Mutex::new(HashSet::new()),
            })
        }

        fn not_installed() -> Arc<Self> {
            Arc::new(Self {
                config_dir: PathBuf::from("/test/config"),
                files: Mutex::new(HashMap::new()),
                calls: Mutex::new(Vec::new()),
                hmac_response: Mutex::new(FAKE_HMAC_RESPONSE.to_string()),
                device_available: false,
                ykman_installed: false,
                deny_read: Mutex::new(HashSet::new()),
                deny_delete: Mutex::new(HashSet::new()),
            })
        }
    }

    #[async_trait::async_trait]
    impl HostPlatform for TestHost {
        async fn exec(
            &self,
            cmd: &str,
            args: &[&str],
            _options: ExecOptions<'_>,
        ) -> Result<ExecOutput, VaultError> {
            assert_eq!(cmd, "ykman", "YubikeyBackend must only ever exec ykman");
            self.calls.lock().unwrap().push(RecordedExec {
                args: args.iter().map(|s| s.to_string()).collect(),
            });

            if !self.ykman_installed {
                return Ok(ExecOutput {
                    stdout: Vec::new(),
                    stderr: b"command not found".to_vec(),
                    exit_code: 127,
                });
            }

            match args.first().copied() {
                Some("--version") => Ok(ExecOutput {
                    stdout: b"YubiKey Manager (ykman) version: 5.4.0".to_vec(),
                    stderr: Vec::new(),
                    exit_code: 0,
                }),
                Some("list") => {
                    if self.device_available {
                        Ok(ExecOutput {
                            stdout: b"YubiKey 5 NFC (5.4.3) [OTP+FIDO+CCID] Serial: 12345".to_vec(),
                            stderr: Vec::new(),
                            exit_code: 0,
                        })
                    } else {
                        Ok(ExecOutput {
                            stdout: Vec::new(),
                            stderr: Vec::new(),
                            exit_code: 0,
                        })
                    }
                }
                Some("otp") => {
                    // ["otp", "calculate", "2", <hex-challenge>]
                    assert_eq!(args.get(1).copied(), Some("calculate"));
                    assert_eq!(args.get(2).copied(), Some("2"));
                    assert!(args.get(3).is_some(), "challenge hex value must be present");
                    let response = self.hmac_response.lock().unwrap().clone();
                    Ok(ExecOutput {
                        stdout: response.into_bytes(),
                        stderr: Vec::new(),
                        exit_code: 0,
                    })
                }
                other => panic!("unexpected ykman invocation: {other:?}"),
            }
        }
        async fn read_file(&self, path: &Path) -> Result<Vec<u8>, VaultError> {
            if self.deny_read.lock().unwrap().contains(path) {
                return Err(VaultError::Filesystem {
                    message: format!("Permission denied reading {}", path.display()),
                    path: path.display().to_string(),
                    permission: "read".to_string(),
                    code: None,
                });
            }
            self.files
                .lock()
                .unwrap()
                .get(path)
                .cloned()
                .ok_or_else(|| VaultError::SecretNotFound {
                    message: format!("Not found: {}", path.display()),
                })
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
            if self.deny_delete.lock().unwrap().contains(path) {
                return Err(VaultError::Filesystem {
                    message: format!("Permission denied deleting {}", path.display()),
                    path: path.display().to_string(),
                    permission: "write".to_string(),
                    code: None,
                });
            }
            self.files
                .lock()
                .unwrap()
                .remove(path)
                .ok_or_else(|| VaultError::SecretNotFound {
                    message: format!("Not found: {}", path.display()),
                })?;
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
            Platform::Darwin
        }
        fn config_dir(&self) -> &Path {
            &self.config_dir
        }
    }

    // ── AC1: argv-sentinel — the secret never reaches ykman argv ──────────

    #[tokio::test]
    async fn store_never_puts_the_secret_in_ykman_argv() {
        let host = TestHost::new();
        let backend = YubikeyBackend::new(host.clone(), false);
        const SENTINEL: &str = "argv-sentinel-should-never-appear-in-args";

        backend.store("sentinel-id", SENTINEL).await.unwrap();

        let calls = host.calls.lock().unwrap();
        assert!(!calls.is_empty());
        for call in calls.iter() {
            assert!(
                call.args.iter().all(|a| !a.contains(SENTINEL)),
                "the secret must never appear in child ykman argv: {:?}",
                call.args
            );
        }
    }

    #[tokio::test]
    async fn store_retrieve_delete_round_trip_never_leaks_secret_into_argv() {
        let host = TestHost::new();
        let backend = YubikeyBackend::new(host.clone(), false);
        const SENTINEL: &str = "super-secret-value-42";

        backend.store("rt-id", SENTINEL).await.unwrap();
        let retrieved = backend.retrieve("rt-id").await.unwrap();
        assert_eq!(retrieved, SENTINEL);
        backend.delete("rt-id").await.unwrap();

        let calls = host.calls.lock().unwrap();
        for call in calls.iter() {
            assert!(
                call.args.iter().all(|a| !a.contains(SENTINEL)),
                "the secret must never appear in child ykman argv at any step: {:?}",
                call.args
            );
            // Only id-derived hex challenge values (and fixed verbs) may
            // appear — every "otp calculate 2 <arg>" argument must be valid
            // hex, never raw text.
            if call.args.first().map(String::as_str) == Some("otp") {
                let challenge = call.args.get(3).expect("challenge arg");
                assert!(
                    challenge.bytes().all(|b| b.is_ascii_hexdigit()),
                    "challenge argv value must be hex, got {challenge}"
                );
            }
        }
    }

    #[tokio::test]
    async fn challenge_argv_is_hex_encoded_vaultkeeper_prefixed_id() {
        let host = TestHost::new();
        let backend = YubikeyBackend::new(host.clone(), false);
        backend.store("my-id", "value").await.unwrap();

        let calls = host.calls.lock().unwrap();
        let otp_call = calls
            .iter()
            .find(|c| c.args.first().map(String::as_str) == Some("otp"))
            .unwrap();
        let expected_challenge = hex_encode(b"vaultkeeper:my-id");
        assert_eq!(otp_call.args[3], expected_challenge);
    }

    // ── AC2: versioned GCM envelope round trip + legacy-CBC detection ─────

    #[tokio::test]
    async fn versioned_gcm_envelope_round_trips() {
        let key = derive_key(FAKE_HMAC_RESPONSE, "id-a").unwrap();
        let encoded = encrypt_gcm_versioned(&key, "hello yubikey").unwrap();
        let parts: Vec<&str> = encoded.split(':').collect();
        assert_eq!(parts.len(), 4);
        assert_eq!(parts[0], "1");
        let decoded = decrypt_gcm_versioned(&key, &encoded, "/fake/path").unwrap();
        assert_eq!(*decoded, "hello yubikey");
    }

    #[tokio::test]
    async fn store_writes_a_versioned_four_part_blob() {
        let host = TestHost::new();
        let backend = YubikeyBackend::new(host.clone(), false);
        backend.store("v-id", "secret-value").await.unwrap();

        let entry_path = backend.entry_path("v-id");
        let raw = host
            .files
            .lock()
            .unwrap()
            .get(&entry_path)
            .cloned()
            .unwrap();
        let text = String::from_utf8(raw).unwrap();
        let parts: Vec<&str> = text.split(':').collect();
        assert_eq!(parts.len(), 4);
        assert_eq!(parts[0], "1");
    }

    /// A real legacy AES-256-CBC blob, produced by the pre-GCM TS backend's
    /// exact old command (`openssl enc -aes-256-cbc -pbkdf2 -pass stdin`,
    /// passphrase = the raw un-derived HMAC hex response, data = plaintext,
    /// both piped over stdin) — not a hand-typed approximation. Regenerate
    /// with:
    ///
    ///   printf 'deadbeefcafe01234567deadbeefcafe01234567\nlegacy-secret-value' \
    ///     | openssl enc -aes-256-cbc -pbkdf2 -pass stdin \
    ///       -out crates/vaultkeeper-core/tests/fixtures/ts-written-yubikey/legacy-cbc.enc
    const LEGACY_CBC_FIXTURE: &[u8] =
        include_bytes!("../../tests/fixtures/ts-written-yubikey/legacy-cbc.enc");

    #[tokio::test]
    async fn legacy_cbc_blob_is_detected_and_surfaces_typed_decryption_error() {
        let host = TestHost::new();
        let backend = YubikeyBackend::new(host.clone(), false);
        let entry_path = backend.entry_path("legacy-id");
        host.files
            .lock()
            .unwrap()
            .insert(entry_path.clone(), LEGACY_CBC_FIXTURE.to_vec());

        let err = backend.retrieve("legacy-id").await.unwrap_err();
        match err {
            VaultError::Decryption { message, path } => {
                assert!(
                    message.contains("legacy format") && message.contains("AES-256-CBC"),
                    "expected a legacy-format message, got: {message}"
                );
                assert_eq!(path, entry_path.display().to_string());
            }
            other => panic!("expected VaultError::Decryption, got {other:?}"),
        }
    }

    #[test]
    fn legacy_content_without_numeric_prefix_is_rejected_directly() {
        // Sanity-check the pure decrypt function against a simple non-binary
        // stand-in, independent of the real OpenSSL fixture above.
        let key = vec![0u8; GCM_KEY_BYTES];
        let err = decrypt_gcm_versioned(&key, "Salted__somebinarycbcdata", "/p").unwrap_err();
        assert!(matches!(err, VaultError::Decryption { .. }));
    }

    #[test]
    fn unsupported_future_version_is_distinguished_from_legacy() {
        let key = vec![0u8; GCM_KEY_BYTES];
        let err = decrypt_gcm_versioned(&key, "42:aXY=:dGFn:Y2lwaGVydGV4dA==", "/p").unwrap_err();
        match err {
            VaultError::Decryption { message, .. } => {
                assert!(
                    message.to_lowercase().contains("unsupported")
                        && message.contains("42")
                        && !message.contains("legacy"),
                    "expected an 'unsupported version' message, not a legacy-format one: {message}"
                );
            }
            other => panic!("expected VaultError::Decryption, got {other:?}"),
        }
    }

    // ── AC3: metadata.json layout + TS-fixture compat ──────────────────────

    const TS_FIXTURE_METADATA: &[u8] =
        include_bytes!("../../tests/fixtures/ts-written-yubikey/metadata.json");
    const TS_FIXTURE_ENTRY: &[u8] = include_bytes!(
        "../../tests/fixtures/ts-written-yubikey/797562696b65792d74732d666978747572652d6964.enc"
    );
    const TS_FIXTURE_ID: &str = "yubikey-ts-fixture-id";
    const TS_FIXTURE_HMAC_RESPONSE: &str = "deadbeefcafe01234567deadbeefcafe01234567";
    const TS_FIXTURE_PLAINTEXT: &str = "ts-core-compat-secret-\u{1F510}";

    #[tokio::test]
    async fn reads_a_metadata_and_entry_pair_written_by_the_ts_backend() {
        let host = TestHost::new();
        *host.hmac_response.lock().unwrap() = TS_FIXTURE_HMAC_RESPONSE.to_string();
        let backend = YubikeyBackend::new(host.clone(), false);

        host.files
            .lock()
            .unwrap()
            .insert(backend.metadata_path(), TS_FIXTURE_METADATA.to_vec());
        host.files
            .lock()
            .unwrap()
            .insert(backend.entry_path(TS_FIXTURE_ID), TS_FIXTURE_ENTRY.to_vec());

        let ids = backend.list().await.unwrap();
        assert_eq!(ids, vec![TS_FIXTURE_ID.to_string()]);

        let secret = backend.retrieve(TS_FIXTURE_ID).await.unwrap();
        assert_eq!(secret, TS_FIXTURE_PLAINTEXT);
    }

    #[tokio::test]
    async fn metadata_written_by_this_port_matches_the_ts_entries_shape() {
        let host = TestHost::new();
        let backend = YubikeyBackend::new(host.clone(), false);
        backend.store("alpha", "val-a").await.unwrap();

        let raw = host
            .files
            .lock()
            .unwrap()
            .get(&backend.metadata_path())
            .cloned()
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        let obj = parsed.as_object().unwrap();
        assert_eq!(
            obj.len(),
            1,
            "metadata.json must have exactly one top-level key: entries"
        );
        let entries = obj.get("entries").unwrap().as_object().unwrap();
        assert!(entries.contains_key("alpha"));
        assert!(entries.get("alpha").unwrap().is_string());
    }

    #[tokio::test]
    async fn list_returns_all_ids_from_metadata_entries() {
        let host = TestHost::new();
        let backend = YubikeyBackend::new(host.clone(), false);
        backend.store("alpha", "val-a").await.unwrap();
        backend.store("beta", "val-b").await.unwrap();
        let mut ids = backend.list().await.unwrap();
        ids.sort();
        assert_eq!(ids, vec!["alpha", "beta"]);
    }

    #[tokio::test]
    async fn list_returns_empty_when_metadata_missing() {
        let host = TestHost::new();
        let backend = YubikeyBackend::new(host, false);
        assert_eq!(backend.list().await.unwrap(), Vec::<String>::new());
    }

    #[tokio::test]
    async fn delete_removes_the_metadata_entry() {
        let host = TestHost::new();
        let backend = YubikeyBackend::new(host.clone(), false);
        backend.store("gone-soon", "value").await.unwrap();
        assert_eq!(backend.list().await.unwrap(), vec!["gone-soon".to_string()]);

        backend.delete("gone-soon").await.unwrap();
        assert_eq!(backend.list().await.unwrap(), Vec::<String>::new());
    }

    // ── AC4: storage dir creation goes through the host write_file path ───

    #[tokio::test]
    async fn store_never_writes_a_keep_sentinel_file() {
        let host = TestHost::new();
        let backend = YubikeyBackend::new(host.clone(), false);
        backend.store("no-sentinel", "value").await.unwrap();

        let files = host.files.lock().unwrap();
        assert!(
            files
                .keys()
                .all(|p| p.file_name().and_then(|n| n.to_str()) != Some(".keep")),
            "must not use a .keep sentinel workaround to force directory creation: {:?}",
            files.keys().collect::<Vec<_>>()
        );
    }

    // ── AC5 (negative): corrupted/truncated blob, missing metadata entry,
    // wrong-key decrypt all surface typed errors, never a garbage secret ───

    #[tokio::test]
    async fn corrupted_ciphertext_surfaces_typed_decryption_error() {
        let host = TestHost::new();
        let backend = YubikeyBackend::new(host.clone(), false);
        backend.store("corrupt-me", "original-value").await.unwrap();

        let entry_path = backend.entry_path("corrupt-me");
        {
            let mut files = host.files.lock().unwrap();
            let data = files.get_mut(&entry_path).unwrap();
            let last = data.len() - 1;
            data[last] ^= 0xff;
        }

        let err = backend.retrieve("corrupt-me").await.unwrap_err();
        assert!(
            matches!(err, VaultError::Decryption { .. }),
            "expected VaultError::Decryption, got {err:?}"
        );
    }

    #[tokio::test]
    async fn truncated_blob_surfaces_typed_decryption_error_not_garbage_secret() {
        let host = TestHost::new();
        let backend = YubikeyBackend::new(host.clone(), false);
        backend
            .store("truncate-me", "original-value")
            .await
            .unwrap();

        let entry_path = backend.entry_path("truncate-me");
        {
            let mut files = host.files.lock().unwrap();
            let data = files.get_mut(&entry_path).unwrap();
            data.truncate(data.len() / 2);
        }

        let err = backend.retrieve("truncate-me").await.unwrap_err();
        assert!(
            matches!(err, VaultError::Decryption { .. }),
            "a truncated blob must never decrypt to a garbage secret: {err:?}"
        );
    }

    #[tokio::test]
    async fn missing_metadata_entry_does_not_block_direct_retrieve_but_list_omits_it() {
        // The TS backend's retrieve()/delete() never consult metadata.json —
        // they recompute the entry path fresh from `id`. metadata.json is
        // purely a `list()` index. A blob that exists on disk but has no
        // metadata entry (e.g. the metadata write failed after the blob
        // write succeeded) must still retrieve correctly, but must not
        // appear in `list()`.
        let host = TestHost::new();
        let backend = YubikeyBackend::new(host.clone(), false);
        let entry_path = backend.entry_path("orphan");
        let key = derive_key(FAKE_HMAC_RESPONSE, "orphan").unwrap();
        let blob = encrypt_gcm_versioned(&key, "orphaned-secret").unwrap();
        host.files
            .lock()
            .unwrap()
            .insert(entry_path, blob.into_bytes());

        assert_eq!(backend.list().await.unwrap(), Vec::<String>::new());
        let retrieved = backend.retrieve("orphan").await.unwrap();
        assert_eq!(retrieved, "orphaned-secret");
    }

    #[tokio::test]
    async fn wrong_key_decrypt_surfaces_typed_error_never_a_garbage_secret() {
        let host = TestHost::new();
        let backend = YubikeyBackend::new(host.clone(), false);
        backend.store("wrong-key-id", "value").await.unwrap();

        // Retrieve with a different HMAC response than what was used to
        // store — simulating a different YubiKey (or a different slot 2
        // configuration) answering the challenge.
        *host.hmac_response.lock().unwrap() =
            "00112233445566778899aabbccddeeff0011223a".to_string();

        let err = backend.retrieve("wrong-key-id").await.unwrap_err();
        assert!(
            matches!(err, VaultError::Decryption { .. }),
            "a wrong-key decrypt must never return a garbage secret: {err:?}"
        );
    }

    #[tokio::test]
    async fn malformed_hmac_response_surfaces_typed_setup_error() {
        let host = TestHost::new();
        *host.hmac_response.lock().unwrap() = "deadbeef".to_string();
        let backend = YubikeyBackend::new(host, false);

        let err = backend.store("id", "value").await.unwrap_err();
        match err {
            VaultError::Setup { dependency, .. } => assert_eq!(dependency, "ykman"),
            other => panic!("expected VaultError::Setup, got {other:?}"),
        }
    }

    // ── Additional coverage: device/plugin errors, capabilities, listing ──

    #[tokio::test]
    async fn store_fails_with_plugin_not_found_when_ykman_missing() {
        let host = TestHost::not_installed();
        let backend = YubikeyBackend::new(host, false);
        let err = backend.store("id", "value").await.unwrap_err();
        assert!(matches!(err, VaultError::PluginNotFound { .. }));
    }

    #[tokio::test]
    async fn store_fails_with_device_not_present_when_no_device_connected() {
        let host = TestHost::unavailable_device();
        let backend = YubikeyBackend::new(host, false);
        let err = backend.store("id", "value").await.unwrap_err();
        assert!(matches!(err, VaultError::DeviceNotPresent { .. }));
    }

    #[tokio::test]
    async fn retrieve_missing_returns_secret_not_found() {
        let host = TestHost::new();
        let backend = YubikeyBackend::new(host, false);
        let err = backend.retrieve("nonexistent").await.unwrap_err();
        assert!(matches!(err, VaultError::SecretNotFound { .. }));
    }

    #[tokio::test]
    async fn delete_missing_returns_secret_not_found() {
        let host = TestHost::new();
        let backend = YubikeyBackend::new(host, false);
        let err = backend.delete("nonexistent").await.unwrap_err();
        assert!(matches!(err, VaultError::SecretNotFound { .. }));
    }

    // ── Act-first TOCTOU: a read/delete failure on an entry that *does*
    // exist (e.g. EACCES/EPERM, surfaced by the host as
    // `VaultError::Filesystem`) must propagate unchanged rather than being
    // misreported as `SecretNotFound` — mirrors
    // `FileBackend::retrieve_permission_denied_returns_filesystem_not_secret_not_found`
    // and `FileBackend::delete_permission_denied_returns_filesystem`. ──────

    #[tokio::test]
    async fn retrieve_permission_denied_returns_filesystem_not_secret_not_found() {
        let host = TestHost::new();
        let backend = YubikeyBackend::new(host.clone(), false);
        backend.store("locked-secret", "value").await.unwrap();
        let entry_path = backend.entry_path("locked-secret");
        host.deny_read.lock().unwrap().insert(entry_path.clone());

        let err = backend.retrieve("locked-secret").await.unwrap_err();
        match err {
            VaultError::Filesystem {
                path, permission, ..
            } => {
                assert_eq!(path, entry_path.display().to_string());
                assert_eq!(permission, "read");
            }
            other => panic!("expected VaultError::Filesystem, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn delete_permission_denied_returns_filesystem_not_secret_not_found() {
        let host = TestHost::new();
        let backend = YubikeyBackend::new(host.clone(), false);
        backend.store("locked-delete", "value").await.unwrap();
        let entry_path = backend.entry_path("locked-delete");
        host.deny_delete.lock().unwrap().insert(entry_path.clone());

        let err = backend.delete("locked-delete").await.unwrap_err();
        match err {
            VaultError::Filesystem {
                path, permission, ..
            } => {
                assert_eq!(path, entry_path.display().to_string());
                assert_eq!(permission, "write");
            }
            other => panic!("expected VaultError::Filesystem, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn exists_does_not_require_a_device() {
        // Matches the TS backend: `exists()` only stats the filesystem, no
        // challenge-response and no `ykman --version`/`list` probe.
        let host = TestHost::unavailable_device();
        let backend = YubikeyBackend::new(host.clone(), false);
        assert!(!backend.exists("id").await.unwrap());
        assert!(host.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn capabilities_reflect_configured_require_touch() {
        let host = TestHost::new();
        let touch_backend = YubikeyBackend::new(host.clone(), true);
        let caps = touch_backend.get_capabilities().await.unwrap();
        assert!(caps.presence_per_use);

        let no_touch_backend = YubikeyBackend::new(host, false);
        let caps = no_touch_backend.get_capabilities().await.unwrap();
        assert!(!caps.presence_per_use);
    }

    #[tokio::test]
    async fn as_presence_capable_returns_self() {
        let host = TestHost::new();
        let backend = YubikeyBackend::new(host, false);
        assert!(crate::backend::is_presence_capable_backend(&backend));
    }

    #[test]
    fn backend_type_and_display_name() {
        let host = TestHost::new();
        let backend = YubikeyBackend::new(host, false);
        assert_eq!(backend.backend_type(), "yubikey");
        assert_eq!(backend.display_name(), "YubiKey");
    }
}
