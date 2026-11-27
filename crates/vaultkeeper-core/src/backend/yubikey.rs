//! YubiKey backend, driven via the `ykman(1)` CLI over [`HostPlatform::exec`].
//!
//! Ports the TypeScript `YubikeyBackend`
//! (`packages/vaultkeeper/src/backend/yubikey-backend.ts`) into
//! `vaultkeeper-core`, preserving its on-disk contract exactly: same
//! entry-path schemes and versioned AES-256-GCM envelopes with a key
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
use std::path::{Path, PathBuf};
use std::sync::Arc;

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64ct::{Base64, Encoding};
use hkdf::Hkdf;
use serde::{Deserialize, Deserializer, de};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::backend::file::hex_encode;
use crate::backend::types::{
    BackendCapabilities, ExecOptions, HostPlatform, ListableBackend, PresenceCapableBackend,
    PresenceOperation, SecretBackend,
};
use crate::errors::VaultError;

const YKMAN_INSTALL_URL: &str = "https://developers.yubico.com/yubikey-manager/";
const STORAGE_SUBDIR: &str = "yubikey";
const DEVICE_TIMEOUT_MS: u64 = 5000;

/// AES-256-GCM constants.
const GCM_IV_BYTES: usize = 12;
const GCM_KEY_BYTES: usize = 32;
const GCM_TAG_BYTES: usize = 16;

/// Version prefix for records whose filename preserves the exact ID spelling.
const FORMAT_VERSION: &str = "1";

/// Records whose UTF-8 path can have several JS spellings carry their exact
/// Base64 UTF-16LE ID as a fifth field and authenticate it as GCM AAD.
const IDENTITY_FORMAT_VERSION: &str = "2";

/// OpenSSL's legacy salted envelope still identifies a record for inventory and cleanup.
const LEGACY_OPENSSL_MAGIC: &[u8] = b"Salted__";

/// A read-only spelling hint for legacy records that predate exact identity filenames.
#[derive(Default, Deserialize)]
struct LegacyIndex {
    entries: BTreeMap<LegacyId, String>,
}

/// Serde's JSON byte-string mode preserves unpaired surrogates as WTF-8.
/// Rust cannot construct these IDs, but it can recognize when a TS record
/// belongs to one instead of to a literal replacement character.
#[derive(Eq, Ord, PartialEq, PartialOrd)]
struct LegacyId(Vec<u8>);

impl<'de> Deserialize<'de> for LegacyId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct IdVisitor;

        impl de::Visitor<'_> for IdVisitor {
            type Value = LegacyId;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a legacy YubiKey ID")
            }

            fn visit_bytes<E: de::Error>(self, bytes: &[u8]) -> Result<LegacyId, E> {
                Ok(LegacyId(bytes.to_vec()))
            }
        }

        deserializer.deserialize_bytes(IdVisitor)
    }
}

impl LegacyIndex {
    /// Only a unique index entry can establish ownership of a lossy filename.
    /// A uniquely identified TypeScript surrogate is outside Rust's ID domain.
    fn addresses(&self, canonical: &str, path: &Path) -> Result<bool, VaultError> {
        let mut matches = self.entries.iter().filter_map(|(key, indexed_path)| {
            // Path prefixes can survive a move or come from another platform.
            let filename = indexed_path.rsplit(['/', '\\']).next();
            (filename.map(std::ffi::OsStr::new) == path.file_name()
                && (key.0 == canonical.as_bytes() || key.normalizes_to(canonical)))
            .then_some(key)
        });
        match (matches.next(), matches.next()) {
            (Some(key), None) => Ok(key.0 == canonical.as_bytes()),
            _ => Err(VaultError::Decryption {
                message: "Ambiguous YubiKey legacy record ID. Restore its original metadata."
                    .to_string(),
                path: path.display().to_string(),
            }),
        }
    }
}

impl LegacyId {
    /// Compare the exact ID against the old UTF-8 path without losing the
    /// distinction between a literal replacement character and a surrogate.
    fn normalizes_to(&self, canonical: &str) -> bool {
        let mut original = self.0.as_slice();
        let mut canonical = canonical.as_bytes();
        let mut replaced = false;
        while let ([byte, rest @ ..], [expected, expected_rest @ ..]) = (original, canonical) {
            if byte == expected {
                original = rest;
                canonical = expected_rest;
            } else if matches!(original, [0xed, 0xa0..=0xbf, 0x80..=0xbf, ..])
                && canonical.starts_with("\u{fffd}".as_bytes())
            {
                original = &original[3..];
                canonical = &canonical[3..];
                replaced = true;
            } else {
                return false;
            }
        }
        replaced && original.is_empty() && canonical.is_empty()
    }
}

/// Expected byte length of a YubiKey HMAC-SHA1 response (20 bytes = 40 hex
/// chars). Must match the TS backend's `HMAC_RESPONSE_HEX_LENGTH` exactly.
const HMAC_RESPONSE_HEX_LENGTH: usize = 40;

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
        match exact_identity(id) {
            Some(identity) => self
                .storage_dir()
                .join(compact_entry_name(id).unwrap_or_else(|| hashed_entry_name(&identity))),
            None => self.legacy_entry_path(id),
        }
    }

    /// Older exact records used the hashed layout even for short IDs.
    fn older_exact_entry_path(&self, id: &str) -> Option<PathBuf> {
        let identity = exact_identity(id)?;
        compact_entry_name(id)?;
        Some(self.storage_dir().join(hashed_entry_name(&identity)))
    }

    /// Older clients encoded every ID using the same UTF-8 filename scheme.
    fn legacy_entry_path(&self, id: &str) -> PathBuf {
        let safe_id = hex_encode(id.as_bytes());
        self.storage_dir().join(format!("{safe_id}.enc"))
    }

    /// Treat only a confirmed absence as missing. An unreadable record is a failed read.
    async fn read_entry(&self, path: &Path) -> Result<Option<Zeroizing<Vec<u8>>>, VaultError> {
        match self.host.read_file(path).await {
            Ok(data) => Ok(Some(Zeroizing::new(data))),
            Err(error) => match self.host.file_exists(path).await {
                Ok(false) => Ok(None),
                Ok(true) | Err(_) => Err(error),
            },
        }
    }

    /// Existence-only host listings can include directories. Skip a positive
    /// directory diagnosis and propagate failures reading actual record candidates.
    async fn read_inventory_entry(
        &self,
        path: &Path,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, VaultError> {
        match self.read_entry(path).await {
            Err(VaultError::Filesystem {
                code: Some(code), ..
            }) if code == "EISDIR" => Ok(None),
            // A host may omit errno. Strict directory enumeration can confirm a
            // directory without hiding errors on regular files or inspecting children.
            Err(VaultError::Filesystem { code: None, .. })
                if self
                    .host
                    .list_dir_for_lowercase_lookup(path, Box::new(|_| false))
                    .await
                    .is_ok() =>
            {
                Ok(None)
            }
            result => result,
        }
    }

    /// Rust can address only the UTF-8 spelling of legacy names. Exact-format
    /// records and other backends' records cannot be used as a legacy fallback.
    async fn read_legacy_entry(
        &self,
        id: &str,
    ) -> Result<Option<(PathBuf, Zeroizing<Vec<u8>>)>, VaultError> {
        if !id.contains('\u{fffd}') {
            return Ok(None);
        }
        let path = self.legacy_entry_path(id);
        // The UTF-8 legacy name can exceed the filesystem's path limits even
        // when the exact name fits. Resolve only the requested legacy name.
        let name = path.file_name().unwrap_or_default().to_owned();
        if self
            .host
            .list_dir_for_lowercase_lookup(
                &self.storage_dir(),
                Box::new(move |entry| name == entry),
            )
            .await?
            .is_empty()
        {
            return Ok(None);
        }
        let Some(data) = self
            .read_inventory_entry(&path)
            .await?
            .filter(|entry| is_legacy_envelope(entry))
        else {
            return Ok(None);
        };
        Ok(self
            .read_legacy_index()
            .await
            .addresses(id, &path)?
            .then_some((path, data)))
    }

    /// Read the direct record layouts in preference order. A generated path that cannot fit
    /// carries no evidence that an older layout is absent.
    async fn read_exact_entry(
        &self,
        id: &str,
    ) -> Result<Option<(PathBuf, Zeroizing<Vec<u8>>)>, VaultError> {
        for path in [Some(self.entry_path(id)), self.older_exact_entry_path(id)]
            .into_iter()
            .flatten()
        {
            match self.read_entry(&path).await {
                Ok(Some(data)) => return Ok(Some((path, data))),
                Err(error)
                    if !self
                        .unaddressable_exact_path_is_absent(id, &path, &error)
                        .await? =>
                {
                    return Err(error);
                }
                _ => (),
            }
        }
        Ok(None)
    }

    /// Check for an older hash before modifying any generation of the record.
    async fn older_path_for_retirement(&self, id: &str) -> Result<Option<PathBuf>, VaultError> {
        if let Some(path) = self.older_exact_entry_path(id) {
            if let Err(error) = self.host.directory_entry_exists(&path).await
                && !self
                    .unaddressable_exact_path_is_absent(id, &path, &error)
                    .await?
            {
                return Err(error);
            }
            return Ok(Some(path));
        }
        Ok(None)
    }

    /// A record at an overlong path can still have been created through a shorter spelling.
    async fn unaddressable_exact_path_is_absent(
        &self,
        id: &str,
        path: &Path,
        error: &VaultError,
    ) -> Result<bool, VaultError> {
        if !id.contains('\u{fffd}')
            || !matches!(error, VaultError::Filesystem { code: Some(code), .. } if code == "ENAMETOOLONG")
        {
            return Ok(false);
        }
        let filename = path.file_name().unwrap_or_default();
        Ok(!self
            .host
            .list_dir(&self.storage_dir())
            .await?
            .iter()
            .any(|name| filename.eq_ignore_ascii_case(name)))
    }

    /// Retire an older generation after publishing its replacement, or before deleting it.
    async fn retire_exact_entry(&self, id: &str, path: &Path) -> Result<bool, VaultError> {
        match self.delete_entry(path).await {
            Err(error)
                if self
                    .unaddressable_exact_path_is_absent(id, path, &error)
                    .await? =>
            {
                Ok(false)
            }
            result => result,
        }
    }

    /// Missing metadata carries no spelling evidence for a lossy legacy filename.
    async fn read_legacy_index(&self) -> LegacyIndex {
        self.host
            .read_file(&self.storage_dir().join("metadata.json"))
            .await
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default()
    }

    /// A delete that loses a race to another delete can proceed to an older generation.
    async fn delete_entry(&self, path: &Path) -> Result<bool, VaultError> {
        match self.host.delete_file(path).await {
            Ok(()) => Ok(true),
            Err(error) => match self.host.file_exists(path).await {
                Ok(false) => Ok(false),
                Ok(true) | Err(_) => Err(error),
            },
        }
    }

    /// Stage a complete regular file so replacing a record never writes through its directory entry.
    async fn publish_entry(&self, path: &Path, encrypted: &[u8]) -> Result<(), VaultError> {
        // The shortest canonical name is `.enc`. Leave room for the `.s`
        // prefix within that same path budget and retry exclusive collisions.
        let suffix_len = path.file_name().unwrap_or_default().len() - 2;
        for _ in 0..16 {
            let mut suffix = [0u8; 12];
            getrandom::fill(&mut suffix).map_err(|e| {
                VaultError::Other(format!("Failed to generate YubiKey stage name: {e}"))
            })?;
            let suffix = hex_encode(&suffix);
            let Some(stage) = self
                .stage_entry(path, encrypted, &suffix, suffix_len)
                .await?
            else {
                continue;
            };
            // Inventory uses the same canonical lookup path even when the
            // filesystem retains an older case spelling after the rename.
            let result = self.host.rename_file(&stage, path).await;
            if result.is_err() {
                let _ = self.host.delete_file(&stage).await;
            }
            return result;
        }
        Err(VaultError::Filesystem {
            message: "Could not reserve a YubiKey staging path".to_string(),
            path: path.display().to_string(),
            permission: "write".to_string(),
            code: Some("EEXIST".to_string()),
        })
    }

    /// Short names require exclusive creation. A legacy host without it keeps
    /// the full random suffix to preserve the private staging namespace.
    async fn stage_entry(
        &self,
        path: &Path,
        encrypted: &[u8],
        suffix: &str,
        suffix_len: usize,
    ) -> Result<Option<PathBuf>, VaultError> {
        let stage = path.with_file_name(format!(".s{}", &suffix[..suffix_len.min(suffix.len())]));
        // This exclusive-create primitive can write a private stage directly.
        // No additional sibling and no hard-link support are needed.
        match self.host.try_create_lock_file(&stage, encrypted).await {
            Ok(()) => return Ok(Some(stage)),
            Err(VaultError::Filesystem {
                code: Some(code), ..
            }) if code == "EEXIST" => return Ok(None),
            Err(VaultError::LockingNotSupported { .. }) => (),
            Err(VaultError::Filesystem {
                message,
                path,
                code,
                ..
            }) => {
                return Err(VaultError::Filesystem {
                    message,
                    path,
                    permission: "write".to_string(),
                    code,
                });
            }
            Err(error) => return Err(error),
        }
        match self
            .host
            .write_file_if_absent(&stage, encrypted, 0o600)
            .await
        {
            Err(VaultError::LockingNotSupported { .. }) => {
                let stage = path.with_file_name(format!(".s{suffix}"));
                if self.host.file_exists(&stage).await? {
                    return Ok(None);
                }
                if let Err(error) = self.host.write_file(&stage, encrypted, 0o600).await {
                    let _ = self.host.delete_file(&stage).await;
                    return Err(error);
                }
                Ok(Some(stage))
            }
            result => result.map(|created| created.then_some(stage)),
        }
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

/// Only U+FFFD is ambiguous for Rust. TypeScript also encodes lone surrogates.
fn exact_identity(id: &str) -> Option<Vec<u8>> {
    id.contains('\u{fffd}').then(|| {
        id.encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>()
    })
}

/// Hash long exact spellings so their filename size stays bounded.
fn hashed_entry_name(identity: &[u8]) -> String {
    format!("id-{}.enc", hex_encode(&Sha256::digest(identity)))
}

/// A compact exact filename uses the same budget as the original hex and `.enc`.
/// Rust scalar IDs have identical UTF-8 and WTF-8 bytes.
fn compact_entry_name(id: &str) -> Option<String> {
    // Only use the compact encoding when it beats `id-<64 hex digits>.enc`.
    (id.len() <= 33).then(|| format!("{}.vk2", hex_encode(id.as_bytes())))
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
// Versioned AES-256-GCM envelope: `1:<iv>:<authTag>:<ciphertext>` or
// `2:<iv>:<authTag>:<ciphertext>:<id>`, with Base64 binary fields.
// ---------------------------------------------------------------------------

fn encrypt_gcm_versioned(
    key: &[u8],
    plaintext: &str,
    identity: Option<&[u8]>,
) -> Result<String, VaultError> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| VaultError::Other(format!("Invalid key: {e}")))?;

    let mut iv = [0u8; GCM_IV_BYTES];
    getrandom::fill(&mut iv)
        .map_err(|e| VaultError::Other(format!("Failed to generate IV: {e}")))?;
    let nonce = Nonce::from_slice(&iv);

    let ciphertext_with_tag = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext.as_bytes(),
                aad: identity.unwrap_or_default(),
            },
        )
        .map_err(|e| VaultError::Other(format!("Encryption failed: {e}")))?;

    let tag_start = ciphertext_with_tag.len() - GCM_TAG_BYTES;
    let ciphertext = &ciphertext_with_tag[..tag_start];
    let auth_tag = &ciphertext_with_tag[tag_start..];

    let version = if identity.is_some() {
        IDENTITY_FORMAT_VERSION
    } else {
        FORMAT_VERSION
    };
    let mut envelope = format!(
        "{version}:{}:{}:{}",
        Base64::encode_string(&iv),
        Base64::encode_string(auth_tag),
        Base64::encode_string(ciphertext),
    );
    if let Some(identity) = identity {
        envelope.push(':');
        envelope.push_str(&Base64::encode_string(identity));
    }
    Ok(envelope)
}

/// Decrypt a versioned GCM blob produced by [`encrypt_gcm_versioned`].
///
/// Version detection distinguishes three cases, matching the TS backend's
/// `decryptGcm` exactly:
/// - First segment identifies a supported GCM version → proceed.
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
    expected_identity: Option<&[u8]>,
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

    let has_identity = version_segment == IDENTITY_FORMAT_VERSION;
    if version_segment != FORMAT_VERSION && !has_identity {
        return Err(VaultError::Decryption {
            message: format!(
                "Unsupported encrypted file version: {version_segment}. This vaultkeeper \
                 build supports versions {FORMAT_VERSION} and {IDENTITY_FORMAT_VERSION}. Upgrade vaultkeeper to read \
                 this secret."
            ),
            path: path.to_string(),
        });
    }
    if has_identity != expected_identity.is_some() {
        return Err(VaultError::Decryption {
            message: "Encrypted file version does not match its record path".to_string(),
            path: path.to_string(),
        });
    }

    if parts.len() != if has_identity { 5 } else { 4 } {
        return Err(VaultError::Decryption {
            message: format!("Invalid encrypted file format for version {version_segment}"),
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
    let identity = if has_identity {
        let invalid_identity = || VaultError::Decryption {
            message: "Invalid encrypted file ID field".to_string(),
            path: path.to_string(),
        };
        let identity = Base64::decode_vec(parts[4]).map_err(|_| invalid_identity())?;
        if identity.is_empty() || !identity.len().is_multiple_of(2) {
            return Err(invalid_identity());
        }
        if Some(identity.as_slice()) != expected_identity {
            return Err(VaultError::Decryption {
                message: "Encrypted file ID does not match the requested ID".to_string(),
                path: path.to_string(),
            });
        }
        identity
    } else {
        Vec::new()
    };

    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| VaultError::Decryption {
        message: format!("Invalid key: {e}"),
        path: path.to_string(),
    })?;
    let nonce = Nonce::from_slice(&iv);

    let mut combined = ciphertext;
    combined.extend_from_slice(&auth_tag);

    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: &combined,
                aad: &identity,
            },
        )
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

        let legacy_path = self.read_legacy_entry(id).await?.map(|(path, _)| path);
        let older_path = self.older_path_for_retirement(id).await?;
        let hmac_response = self.challenge_response(id).await?;
        let key = derive_key(&hmac_response, id)?;
        let identity = exact_identity(id);
        let encrypted = encrypt_gcm_versioned(&key, secret, identity.as_deref())?;

        self.publish_entry(&self.entry_path(id), encrypted.as_bytes())
            .await?;
        if let Some(path) = legacy_path {
            // Keep the old value until the exact replacement is published.
            self.delete_entry(&path).await?;
        }
        if let Some(path) = older_path {
            self.retire_exact_entry(id, &path).await?;
        }
        Ok(())
    }

    async fn retrieve(&self, id: &str) -> Result<String, VaultError> {
        self.require_device().await?;

        let (entry_path, data) = match self.read_exact_entry(id).await? {
            Some(entry) => entry,
            None => {
                self.read_legacy_entry(id)
                    .await?
                    .ok_or_else(|| VaultError::SecretNotFound {
                        message: format!("Secret not found in YubiKey store: {id}"),
                    })?
            }
        };
        // The stored entry is UTF-8 text by design for the current versioned
        // format, but a legacy pre-GCM entry is raw OpenSSL binary output —
        // lossily decode (never hard-fail here) so a legacy/corrupt blob
        // still reaches `decrypt_gcm_versioned`'s version-detection branch
        // and surfaces the intended typed error, matching the TS backend's
        // `fs.readFile(path, 'utf8')` (which never throws on invalid UTF-8).
        let encoded = String::from_utf8_lossy(&data);

        let hmac_response = self.challenge_response(id).await?;
        let key = derive_key(&hmac_response, id)?;

        let identity = if entry_path == self.legacy_entry_path(id) {
            None
        } else {
            exact_identity(id)
        };
        let plaintext = decrypt_gcm_versioned(
            &key,
            &encoded,
            identity.as_deref(),
            &entry_path.display().to_string(),
        )?;
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

        let older_path = self.older_path_for_retirement(id).await?;
        // Delete the older generation first so it cannot be revealed after
        // deleting the exact record. A store of another spelling uses its own
        // exact path and cannot overwrite this confirmed legacy record.
        let legacy_deleted = match self.read_legacy_entry(id).await? {
            Some((path, _)) => self.delete_entry(&path).await?,
            None => false,
        };
        let older_deleted = match older_path {
            Some(path) => self.retire_exact_entry(id, &path).await?,
            None => false,
        };
        let current = self.entry_path(id);
        let exact_deleted = if legacy_deleted || older_deleted {
            self.retire_exact_entry(id, &current).await?
        } else {
            self.delete_entry(&current).await?
        };
        if exact_deleted || legacy_deleted || older_deleted {
            Ok(())
        } else {
            Err(VaultError::SecretNotFound {
                message: format!("Secret not found in YubiKey store: {id}"),
            })
        }
    }

    async fn exists(&self, id: &str) -> Result<bool, VaultError> {
        for path in [Some(self.entry_path(id)), self.older_exact_entry_path(id)]
            .into_iter()
            .flatten()
        {
            match self.host.file_exists(&path).await {
                Ok(true) => return Ok(true),
                Err(error)
                    if !self
                        .unaddressable_exact_path_is_absent(id, &path, &error)
                        .await? =>
                {
                    return Err(error);
                }
                _ => (),
            }
        }
        Ok(self.read_legacy_entry(id).await?.is_some())
    }

    fn as_presence_capable(&self) -> Option<&dyn PresenceCapableBackend> {
        Some(self)
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl ListableBackend for YubikeyBackend {
    async fn list(&self) -> Result<Vec<String>, VaultError> {
        // The entry files are authoritative; the old shared index can be
        // stale after concurrent writes or an interrupted metadata update.
        let storage_dir = self.storage_dir();
        let mut ids = Vec::new();
        let mut legacy_index = None;
        for filename in self
            .host
            .list_dir_for_lowercase_lookup(&storage_dir, Box::new(is_legacy_record_name))
            .await?
        {
            let Some(id) = legacy_record_id(&filename) else {
                continue;
            };
            let path = storage_dir.join(&filename);
            if !self
                .read_inventory_entry(&path)
                .await?
                .is_some_and(|entry| is_legacy_envelope(&entry))
            {
                continue;
            }
            if id.contains('\u{fffd}') {
                let index = match &legacy_index {
                    Some(index) => index,
                    None => legacy_index.insert(self.read_legacy_index().await),
                };
                if !index.addresses(&id, &path)? {
                    continue;
                }
            }
            ids.push(id);
        }

        // Scan each layout after its predecessors. Publication always precedes retirement.
        let exact_layouts: [fn(&str) -> bool; 2] = [is_hashed_record_name, is_compact_record_name];
        for include in exact_layouts {
            for filename in self
                .host
                .list_dir_for_lowercase_lookup(&storage_dir, Box::new(include))
                .await?
            {
                if include(&filename) {
                    let path = storage_dir.join(&filename);
                    if let Some(entry) = self.read_inventory_entry(&path).await?
                        && let Some(id) = exact_envelope_id(&entry, &filename, &path)?
                    {
                        ids.push(id);
                    }
                }
            }
        }
        ids.sort();
        ids.dedup();
        Ok(ids)
    }
}

/// Only a decodable legacy name can identify a record worth opening.
fn is_legacy_record_name(name: &str) -> bool {
    legacy_record_id(name).is_some()
}

/// A legacy filename encodes the UTF-8 bytes of the ID, including the empty ID.
fn legacy_record_id(name: &str) -> Option<String> {
    let hex = name.strip_suffix(".enc").filter(|hex| is_record_hex(hex))?;
    String::from_utf8(hex_decode(hex).ok()?).ok()
}

/// An exact filename encodes the SHA-256 digest of the original spelling.
fn is_hashed_record_name(name: &str) -> bool {
    name.strip_prefix("id-")
        .and_then(|name| name.strip_suffix(".enc"))
        .is_some_and(|hex| hex.len() == 64 && is_record_hex(hex))
}

/// Rust's compact records are named by a short, valid UTF-8 spelling containing U+FFFD.
fn is_compact_record_name(name: &str) -> bool {
    compact_record_id(name).is_some()
}

/// The compact filename can recover its exact scalar ID independently of the ciphertext.
fn compact_record_id(name: &str) -> Option<String> {
    name.strip_suffix(".vk2")
        .filter(|hex| hex.len() <= 66 && is_record_hex(hex))
        .and_then(|hex| String::from_utf8(hex_decode(hex).ok()?).ok())
        .filter(|id| id.contains('\u{fffd}'))
}

/// Canonical record names encode whole bytes in lowercase hexadecimal.
fn is_record_hex(hex: &str) -> bool {
    hex.len().is_multiple_of(2)
        && hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The version or legacy magic identifies ownership without a device touch or
/// successful decryption. Other backends can use the same filename scheme.
fn is_legacy_envelope(entry: &[u8]) -> bool {
    // A v1 marker survives truncation and cannot be a FileBackend's 12-byte IV.
    if entry.starts_with(LEGACY_OPENSSL_MAGIC) || entry.starts_with(b"1:") {
        return true;
    }
    let mut fields = entry.splitn(5, |&byte| byte == b':');
    let Some(version) = fields.next() else {
        return false;
    };
    // FileBackend's three-field envelope can have an all-digit Base64 IV.
    !version.is_empty()
        && version != IDENTITY_FORMAT_VERSION.as_bytes()
        && version.iter().all(u8::is_ascii_digit)
        && fields.count() == 3
}

/// Recover the ID of a recognized exact record. A hash needs a verifiable
/// spelling before inventory can distinguish corruption from a TypeScript-only ID.
fn exact_envelope_id(
    entry: &[u8],
    filename: &str,
    path: &Path,
) -> Result<Option<String>, VaultError> {
    if !entry.starts_with(b"2:") {
        return Ok(None);
    }
    // A surviving version marker identifies a compact record even if it lost its AAD field.
    if let Some(id) = compact_record_id(filename) {
        return Ok(Some(id));
    }
    let unidentifiable = || VaultError::Decryption {
        message: "Cannot identify the YubiKey hashed record.".to_string(),
        path: path.display().to_string(),
    };
    let identity = entry
        .splitn(5, |&byte| byte == b':')
        .nth(4)
        .and_then(|encoded| std::str::from_utf8(encoded).ok())
        .and_then(|encoded| Base64::decode_vec(encoded).ok())
        .ok_or_else(unidentifiable)?;
    let (units, remainder) = identity.as_chunks::<2>();
    if units.is_empty() || !remainder.is_empty() || hashed_entry_name(&identity) != filename {
        return Err(unidentifiable());
    }
    let units: Vec<_> = units.iter().copied().map(u16::from_le_bytes).collect();
    // A hash-confirmed spelling with an unpaired surrogate is outside Rust's ID domain.
    match String::from_utf16(&units) {
        Ok(id) if id.contains('\u{fffd}') => Ok(Some(id)),
        Ok(_) => Err(unidentifiable()),
        Err(_) => Ok(None),
    }
}

/// `presence_per_use` is `true` only when the configured slot enforces a
/// touch-per-operation policy (`require_touch`), matching the TS backend's
/// `getCapabilities` exactly: the answer always comes from the
/// operator-declared configuration, never derived from the backend type
/// alone.
///
/// **Operation coverage (issue #326):** the touch-per-operation policy only
/// actually fires for `store()` and `retrieve()` — both perform the
/// HMAC-SHA1 challenge-response (`ykman otp calculate 2 ...`) that demands
/// the physical tap. [`SecretBackend::delete`] only calls `require_device()`
/// (a presence *probe*: is a YubiKey plugged in at all) plus a filesystem
/// unlink — it never invokes challenge-response, so it never actually
/// demands a fresh touch. Reporting `presence_enforced_operations: None`
/// (meaning "all keyed operations") would therefore be dishonest: a caller
/// relying on `presencePerUse` to mean "deleting this secret requires a
/// physical touch" would be misled. This reports
/// `Some([PresenceOperation::Read, PresenceOperation::Store])`, excluding
/// `Delete`, so a `--require-presence-per-use` delete fails closed via
/// [`crate::vault::enforce_presence_requirement`] instead of silently
/// succeeding with no touch. `Sign` does not apply — this backend does not
/// implement `SigningBackend`.
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl PresenceCapableBackend for YubikeyBackend {
    async fn get_capabilities(&self) -> Result<BackendCapabilities, VaultError> {
        Ok(BackendCapabilities {
            presence_per_use: self.require_touch,
            presence_enforced_operations: self
                .require_touch
                .then(|| vec![PresenceOperation::Read, PresenceOperation::Store]),
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

    /// Pauses an inventory after it has captured the filesystem names.
    struct DirectorySnapshot {
        captured: tokio::sync::oneshot::Sender<()>,
        release: tokio::sync::oneshot::Receiver<()>,
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
        /// Canonical lookup paths that resolve to a differently cased raw file name.
        case_aliases: Mutex<HashMap<PathBuf, PathBuf>>,
        /// Raw directory entries whose paths exist but cannot be read as files.
        directories: Mutex<HashMap<PathBuf, Option<&'static str>>>,
        /// Synchronizes legacy index reads to expose lost read-modify-write updates.
        metadata_barrier: Mutex<Option<Arc<tokio::sync::Barrier>>>,
        directory_snapshot: Mutex<Option<DirectorySnapshot>>,
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
                case_aliases: Mutex::new(HashMap::new()),
                directories: Mutex::new(HashMap::new()),
                metadata_barrier: Mutex::new(None),
                directory_snapshot: Mutex::new(None),
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
                case_aliases: Mutex::new(HashMap::new()),
                directories: Mutex::new(HashMap::new()),
                metadata_barrier: Mutex::new(None),
                directory_snapshot: Mutex::new(None),
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
                case_aliases: Mutex::new(HashMap::new()),
                directories: Mutex::new(HashMap::new()),
                metadata_barrier: Mutex::new(None),
                directory_snapshot: Mutex::new(None),
            })
        }

        /// Resolve a test's case-only rename without changing raw directory enumeration.
        fn resolved_path(&self, path: &Path) -> PathBuf {
            self.case_aliases
                .lock()
                .unwrap()
                .get(path)
                .cloned()
                .unwrap_or_else(|| path.to_path_buf())
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

            // Ported onto the generalized `StubTool` engine (issue #313
            // AC6): this used to be a hand-written match over `args.first()`
            // — now it's the exact same `ykman` behavior table
            // `vk-stub-ykman` (a real subprocess binary) loads, driven
            // in-process here for speed/hermeticity. `device_available` and
            // `hmac_response` seed a fresh `World` per call rather than
            // persisting one across calls, matching this double's original
            // per-call semantics (`hmac_response` can be swapped mid-test —
            // see e.g. `wrong_key_decrypt_surfaces_typed_error_never_a_garbage_secret`).
            let hmac_response = self.hmac_response.lock().unwrap().clone();
            let table = vaultkeeper_stub_tools::tables::ykman(&hmac_response);
            let mut world = vaultkeeper_stub_tools::World::new();
            world.flags.insert(
                vaultkeeper_stub_tools::tables::YKMAN_DEVICE_AVAILABLE_FLAG.to_string(),
                self.device_available,
            );
            let args_owned: Vec<String> = args.iter().map(|s| s.to_string()).collect();
            let result =
                vaultkeeper_stub_tools::StubTool::run(&table, &mut world, &args_owned, b"");

            if result.exit_code == vaultkeeper_stub_tools::NO_MATCH_EXIT_CODE {
                panic!("unexpected ykman invocation: {args_owned:?}");
            }

            Ok(ExecOutput {
                stdout: result.stdout,
                stderr: result.stderr,
                exit_code: result.exit_code,
            })
        }
        async fn read_file(&self, path: &Path) -> Result<Vec<u8>, VaultError> {
            let path = &self.resolved_path(path);
            if self.deny_read.lock().unwrap().contains(path) {
                return Err(VaultError::Filesystem {
                    message: format!("Permission denied reading {}", path.display()),
                    path: path.display().to_string(),
                    permission: "read".to_string(),
                    code: None,
                });
            }
            if let Some(code) = self.directories.lock().unwrap().get(path) {
                return Err(VaultError::Filesystem {
                    message: format!("Is a directory: {}", path.display()),
                    path: path.display().to_string(),
                    permission: "read".to_string(),
                    code: code.map(String::from),
                });
            }
            let result = self
                .files
                .lock()
                .unwrap()
                .get(path)
                .cloned()
                .ok_or_else(|| VaultError::SecretNotFound {
                    message: format!("Not found: {}", path.display()),
                });
            let barrier = if path.file_name().is_some_and(|name| name == "metadata.json") {
                self.metadata_barrier.lock().unwrap().clone()
            } else {
                None
            };
            if let Some(barrier) = barrier {
                barrier.wait().await;
            }
            result
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
            // Model a filesystem that rejects overlong legacy path components.
            if path.file_name().is_some_and(|name| name.len() > 255) {
                return Err(VaultError::Filesystem {
                    message: "Filename too long".to_string(),
                    path: path.display().to_string(),
                    permission: "read".to_string(),
                    code: None,
                });
            }
            let path = &self.resolved_path(path);
            Ok(self.files.lock().unwrap().contains_key(path)
                || self.directories.lock().unwrap().contains_key(path))
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
            // A successful listing distinguishes a directory from an existing regular file.
            if self
                .files
                .lock()
                .unwrap()
                .contains_key(&self.resolved_path(path))
            {
                return Err(VaultError::Filesystem {
                    message: format!("Not a directory: {}", path.display()),
                    path: path.display().to_string(),
                    permission: "read".to_string(),
                    code: Some("ENOTDIR".to_string()),
                });
            }
            let filenames = self
                .files
                .lock()
                .unwrap()
                .keys()
                .chain(self.directories.lock().unwrap().keys())
                .filter_map(|k| {
                    if k.parent() == Some(path) {
                        k.file_name().and_then(|n| n.to_str()).map(String::from)
                    } else {
                        None
                    }
                })
                .collect();
            let snapshot = self.directory_snapshot.lock().unwrap().take();
            if let Some(snapshot) = snapshot {
                snapshot.captured.send(()).unwrap();
                snapshot.release.await.unwrap();
            }
            Ok(filenames)
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
        let encoded = encrypt_gcm_versioned(&key, "hello yubikey", None).unwrap();
        let parts: Vec<&str> = encoded.split(':').collect();
        assert_eq!(parts.len(), 4);
        assert_eq!(parts[0], "1");
        let decoded = decrypt_gcm_versioned(&key, &encoded, None, "/fake/path").unwrap();
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
        let err = decrypt_gcm_versioned(&key, "Salted__somebinarycbcdata", None, "/p").unwrap_err();
        assert!(matches!(err, VaultError::Decryption { .. }));
    }

    #[test]
    fn unsupported_future_version_is_distinguished_from_legacy() {
        let key = vec![0u8; GCM_KEY_BYTES];
        let err =
            decrypt_gcm_versioned(&key, "42:aXY=:dGFn:Y2lwaGVydGV4dA==", None, "/p").unwrap_err();
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
    async fn inventory_excludes_other_envelopes_and_keeps_openssl_records() {
        let host = TestHost::new();
        let backend = YubikeyBackend::new(host.clone(), false);
        backend.store("current", "value").await.unwrap();
        host.files.lock().unwrap().extend([
            (
                backend.entry_path("foreign"),
                b"1234567890123456:AAAAAAAAAAAAAAAAAAAAAA==:AA==".to_vec(),
            ),
            (backend.entry_path("legacy"), LEGACY_CBC_FIXTURE.to_vec()),
        ]);

        let mut ids = backend.list().await.unwrap();
        ids.sort();
        assert_eq!(ids, ["current", "legacy"]);
    }

    /// A raw uppercase name belongs in inventory only when canonical lookup reaches it.
    #[tokio::test]
    async fn default_host_inventory_resolves_reachable_case_aliases() {
        let host = TestHost::new();
        let backend = YubikeyBackend::new(host.clone(), false);
        backend.store("alpha", "first value").await.unwrap();
        backend.store("beta", "second value").await.unwrap();
        let canonical = backend.entry_path("beta");
        let uppercase = backend.storage_dir().join("62657461.ENC");
        host.rename_file(&canonical, &uppercase).await.unwrap();
        assert_eq!(backend.list().await.unwrap(), ["alpha"]);

        host.case_aliases
            .lock()
            .unwrap()
            .insert(canonical, uppercase);
        assert!(backend.exists("beta").await.unwrap());
        assert_eq!(backend.retrieve("beta").await.unwrap(), "second value");
        assert_eq!(backend.list().await.unwrap(), ["alpha", "beta"]);
    }

    /// A directory read can fail with or without errno while genuine file read errors propagate.
    #[tokio::test]
    async fn default_host_inventory_ignores_directories_named_like_records() {
        let host = TestHost::new();
        let backend = YubikeyBackend::new(host.clone(), false);
        backend.store("alpha", "first value").await.unwrap();
        backend.store("beta", "second value").await.unwrap();
        let directory = backend.entry_path("c");
        host.directories.lock().unwrap().extend([
            (directory.clone(), Some("EISDIR")),
            (backend.entry_path("d"), None),
        ]);
        assert!(host.file_exists(&directory).await.unwrap());

        assert_eq!(backend.list().await.unwrap(), ["alpha", "beta"]);
        let unreadable = backend.entry_path("beta");
        host.deny_read.lock().unwrap().insert(unreadable.clone());
        assert!(matches!(
            backend.list().await,
            Err(VaultError::Filesystem { path, .. }) if path == unreadable.to_string_lossy()
        ));
    }

    /// A recognized hashed record can require operator cleanup after its spelling is damaged.
    #[tokio::test]
    async fn inventory_reports_an_unidentifiable_hashed_record() {
        let host = TestHost::new();
        let backend = YubikeyBackend::new(host.clone(), false);
        let id = format!("{}\u{fffd}", "a".repeat(31));
        backend.store("alpha", "first value").await.unwrap();
        backend.store(&id, "second value").await.unwrap();
        let record = backend.entry_path(&id);
        assert!(is_hashed_record_name(
            record.file_name().unwrap().to_str().unwrap()
        ));

        let reopened = YubikeyBackend::new(host.clone(), false);
        assert_eq!(reopened.list().await.unwrap(), [id.as_str(), "alpha"]);
        assert_eq!(reopened.retrieve(&id).await.unwrap(), "second value");
        let data = Zeroizing::new(host.read_file(&record).await.unwrap());
        let fields = std::str::from_utf8(&data).unwrap();
        let (envelope, _) = fields.rsplit_once(':').unwrap();
        let wrong_spelling = Zeroizing::new(format!("{envelope}:/f8="));
        for damaged in [&data[..12], wrong_spelling.as_bytes()] {
            host.write_file(&record, damaged, 0o600).await.unwrap();
            assert!(reopened.exists(&id).await.unwrap());
            assert!(matches!(
                reopened.retrieve(&id).await,
                Err(VaultError::Decryption { .. })
            ));
            let result = reopened.list().await;
            assert!(
                matches!(
                    result,
                    Err(VaultError::Decryption { ref path, .. }) if path == &record.to_string_lossy()
                ),
                "expected a typed error for the hashed path, got {result:?}"
            );
        }
        reopened.delete(&id).await.unwrap();
        assert_eq!(reopened.list().await.unwrap(), ["alpha"]);
    }

    /// A hash-verified TypeScript ID with an unpaired surrogate is outside Rust's ID domain.
    #[tokio::test]
    async fn rust_inventory_skips_identified_typescript_only_hashes() {
        let host = TestHost::new();
        let backend = YubikeyBackend::new(host.clone(), false);
        backend.store("alpha", "value").await.unwrap();
        let identity = 0xd800_u16.to_le_bytes();
        let record = backend.storage_dir().join(hashed_entry_name(&identity));
        let envelope = format!("2:iv:tag:ciphertext:{}", Base64::encode_string(&identity));
        host.write_file(&record, envelope.as_bytes(), 0o600)
            .await
            .unwrap();

        assert_eq!(backend.list().await.unwrap(), ["alpha"]);
    }

    #[tokio::test]
    async fn replacement_character_records_carry_spelling_for_typescript_inventory() {
        let host = TestHost::new();
        let backend = YubikeyBackend::new(host.clone(), false);
        let id = "\u{fffd}";
        backend.store(id, "value").await.unwrap();
        let bytes = host.read_file(&backend.entry_path(id)).await.unwrap();
        let encoded = String::from_utf8(bytes).unwrap();

        assert!(encoded.starts_with("2:"));
        assert_eq!(encoded.split(':').next_back(), Some("/f8="));
        assert_eq!(backend.entry_path(id).file_name().unwrap(), "efbfbd.vk2");
        assert_eq!(backend.list().await.unwrap(), [id]);
        assert_eq!(backend.retrieve(id).await.unwrap(), "value");
    }

    /// A compact record can replace an older hashed record without reviving its value on delete.
    #[tokio::test]
    async fn compact_entries_read_and_retire_older_hashed_records() {
        let host = TestHost::new();
        let backend = YubikeyBackend::new(host.clone(), false);
        let id = "\u{fffd}";
        let current_path = backend.entry_path(id);
        let older_path = backend.older_exact_entry_path(id).unwrap();
        backend.store(id, "old value").await.unwrap();
        host.rename_file(&current_path, &older_path).await.unwrap();

        let reopened = YubikeyBackend::new(host.clone(), false);
        assert_eq!(reopened.list().await.unwrap(), [id]);
        assert!(reopened.exists(id).await.unwrap());
        assert_eq!(reopened.retrieve(id).await.unwrap(), "old value");
        reopened.store(id, "new value").await.unwrap();
        assert!(!host.file_exists(&older_path).await.unwrap());
        assert_eq!(reopened.retrieve(id).await.unwrap(), "new value");
        reopened.delete(id).await.unwrap();
        assert!(!reopened.exists(id).await.unwrap());
    }

    #[tokio::test]
    async fn rust_does_not_delete_a_legacy_typescript_alias_as_a_literal_replacement() {
        let host = TestHost::new();
        let backend = YubikeyBackend::new(host.clone(), false);
        let id = "\u{fffd}";
        let legacy_path = backend.legacy_entry_path(id);
        let key = derive_key(FAKE_HMAC_RESPONSE, id).unwrap();
        let legacy = encrypt_gcm_versioned(&key, "legacy value", None).unwrap();
        host.files.lock().unwrap().extend([
            (legacy_path.clone(), legacy.as_bytes().to_vec()),
            (
                backend.storage_dir().join("metadata.json"),
                br#"{"entries":{"\ud800":"efbfbd.enc"}}"#.to_vec(),
            ),
        ]);

        assert!(!backend.exists(id).await.unwrap());
        assert!(backend.list().await.unwrap().is_empty());
        backend.store(id, "canonical value").await.unwrap();
        assert_eq!(backend.retrieve(id).await.unwrap(), "canonical value");
        backend.delete(id).await.unwrap();
        assert_eq!(
            host.read_file(&legacy_path).await.unwrap(),
            legacy.as_bytes()
        );
    }

    /// A lossy filename cannot establish ownership when the legacy index is damaged.
    #[tokio::test]
    async fn corrupt_legacy_index_does_not_reassign_a_typescript_alias() {
        let host = TestHost::new();
        let backend = YubikeyBackend::new(host.clone(), false);
        let id = "\u{fffd}";
        let legacy_path = backend.legacy_entry_path(id);
        let key = derive_key(FAKE_HMAC_RESPONSE, id).unwrap();
        let legacy = encrypt_gcm_versioned(&key, "legacy value", None).unwrap();
        let metadata_path = backend.storage_dir().join("metadata.json");
        host.files.lock().unwrap().extend([
            (legacy_path.clone(), legacy.as_bytes().to_vec()),
            (
                metadata_path.clone(),
                br#"{"entries":{"\ud800":"efbfbd.enc"}}"#.to_vec(),
            ),
        ]);
        assert!(backend.list().await.unwrap().is_empty());
        host.write_file(&metadata_path, b"{broken", 0o600)
            .await
            .unwrap();

        let reopened = YubikeyBackend::new(host.clone(), false);
        assert!(matches!(
            reopened.list().await,
            Err(VaultError::Decryption { .. })
        ));
        assert!(matches!(
            reopened.exists(id).await,
            Err(VaultError::Decryption { .. })
        ));
        assert!(matches!(
            reopened.retrieve(id).await,
            Err(VaultError::Decryption { .. })
        ));
        assert!(matches!(
            reopened.delete(id).await,
            Err(VaultError::Decryption { .. })
        ));
        assert_eq!(
            host.read_file(&legacy_path).await.unwrap(),
            legacy.as_bytes()
        );
    }

    /// Replacing a confirmed legacy scalar record retires it before the index can be lost.
    #[tokio::test]
    async fn upgraded_legacy_replacement_character_does_not_leave_an_obsolete_record() {
        let host = TestHost::new();
        let backend = YubikeyBackend::new(host.clone(), false);
        let id = "\u{fffd}";
        let legacy_path = backend.legacy_entry_path(id);
        let metadata_path = backend.storage_dir().join("metadata.json");
        let key = derive_key(FAKE_HMAC_RESPONSE, id).unwrap();
        let legacy = encrypt_gcm_versioned(&key, "legacy value", None).unwrap();
        host.files.lock().unwrap().extend([
            (legacy_path.clone(), legacy.as_bytes().to_vec()),
            (
                metadata_path.clone(),
                br#"{"entries":{"\ufffd":"efbfbd.enc"}}"#.to_vec(),
            ),
        ]);
        assert_eq!(backend.retrieve(id).await.unwrap(), "legacy value");
        backend.store(id, "new value").await.unwrap();
        assert!(!host.file_exists(&legacy_path).await.unwrap());
        host.write_file(&metadata_path, b"{broken", 0o600)
            .await
            .unwrap();

        let reopened = YubikeyBackend::new(host.clone(), false);
        assert_eq!(reopened.list().await.unwrap(), [id]);
        assert_eq!(reopened.retrieve(id).await.unwrap(), "new value");
        reopened.delete(id).await.unwrap();
        assert!(reopened.list().await.unwrap().is_empty());
        assert!(!host.file_exists(&legacy_path).await.unwrap());
    }

    /// Stale path values cannot transfer ownership of a still-present legacy record.
    #[tokio::test]
    async fn legacy_index_with_wrong_filename_cannot_reassign_or_retire_a_record() {
        let host = TestHost::new();
        let backend = YubikeyBackend::new(host.clone(), false);
        let id = "\u{fffd}";
        let legacy_path = backend.legacy_entry_path(id);
        host.files.lock().unwrap().extend([
            (legacy_path.clone(), LEGACY_CBC_FIXTURE.to_vec()),
            (
                backend.storage_dir().join("metadata.json"),
                br#"{"entries":{"\ufffd":"unrelated.enc"}}"#.to_vec(),
            ),
        ]);

        assert!(matches!(
            backend.list().await,
            Err(VaultError::Decryption { .. })
        ));
        assert!(matches!(
            backend.store(id, "value").await,
            Err(VaultError::Decryption { .. })
        ));
        assert_eq!(
            host.read_file(&legacy_path).await.unwrap(),
            LEGACY_CBC_FIXTURE
        );
    }

    /// Inventory may observe either generation during migration, while the ID stays present.
    #[tokio::test]
    async fn inventory_keeps_a_legacy_record_while_another_instance_upgrades_it() {
        let host = TestHost::new();
        let backend = YubikeyBackend::new(host.clone(), false);
        let id = "\u{fffd}";
        host.files.lock().unwrap().extend([
            (backend.legacy_entry_path(id), LEGACY_CBC_FIXTURE.to_vec()),
            (
                backend.storage_dir().join("metadata.json"),
                br#"{"entries":{"\ufffd":"efbfbd.enc"}}"#.to_vec(),
            ),
        ]);
        let (captured, ready) = tokio::sync::oneshot::channel();
        let (resume, release) = tokio::sync::oneshot::channel();
        *host.directory_snapshot.lock().unwrap() = Some(DirectorySnapshot { captured, release });
        let inventory = tokio::spawn(async move { YubikeyBackend::new(host, false).list().await });
        ready.await.unwrap();
        backend.store(id, "value").await.unwrap();
        resume.send(()).unwrap();

        assert_eq!(inventory.await.unwrap().unwrap(), [id]);
    }

    #[tokio::test]
    async fn deletes_an_exact_record_with_an_unaddressable_legacy_filename() {
        let host = TestHost::new();
        let backend = YubikeyBackend::new(host.clone(), false);
        let id = "\u{fffd}".repeat(50);
        backend.store(&id, "value").await.unwrap();
        let reopened = YubikeyBackend::new(host, false);
        assert_eq!(reopened.list().await.unwrap(), [id.as_str()]);
        assert_eq!(reopened.retrieve(&id).await.unwrap(), "value");
        reopened.delete(&id).await.unwrap();
        assert!(!reopened.exists(&id).await.unwrap());
        assert!(reopened.list().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn inventory_survives_stale_or_unreadable_metadata() {
        let host = TestHost::new();
        let first = YubikeyBackend::new(host.clone(), false);
        let second = YubikeyBackend::new(host.clone(), false);
        *host.metadata_barrier.lock().unwrap() = Some(Arc::new(tokio::sync::Barrier::new(2)));
        let (a, b) = tokio::join!(first.store("alpha", "a"), second.store("beta", "b"));
        a.unwrap();
        b.unwrap();
        *host.metadata_barrier.lock().unwrap() = None;
        let mut ids = YubikeyBackend::new(host.clone(), false)
            .list()
            .await
            .unwrap();
        ids.sort();
        assert_eq!(ids, vec!["alpha", "beta"]);
        let metadata_path = first.storage_dir().join("metadata.json");
        host.files
            .lock()
            .unwrap()
            .insert(metadata_path.clone(), b"broken".to_vec());
        host.deny_read.lock().unwrap().insert(metadata_path);
        host.files
            .lock()
            .unwrap()
            .insert(first.storage_dir().join("aéa.enc"), vec![]);
        let reopened = YubikeyBackend::new(host, false);
        let mut ids = reopened.list().await.unwrap();
        ids.sort();
        assert_eq!(ids, vec!["alpha", "beta"]);
    }

    #[tokio::test]
    async fn lists_and_retrieves_a_legacy_record_written_by_typescript() {
        let host = TestHost::new();
        *host.hmac_response.lock().unwrap() = TS_FIXTURE_HMAC_RESPONSE.to_string();
        let backend = YubikeyBackend::new(host.clone(), false);

        host.files.lock().unwrap().insert(
            backend.storage_dir().join("metadata.json"),
            TS_FIXTURE_METADATA.to_vec(),
        );
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
    async fn list_returns_all_stored_record_ids() {
        let host = TestHost::new();
        let backend = YubikeyBackend::new(host.clone(), false);
        backend.store("alpha", "val-a").await.unwrap();
        backend.store("beta", "val-b").await.unwrap();
        let mut ids = backend.list().await.unwrap();
        ids.sort();
        assert_eq!(ids, vec!["alpha", "beta"]);
    }

    #[tokio::test]
    async fn list_returns_empty_when_no_records_exist() {
        let host = TestHost::new();
        let backend = YubikeyBackend::new(host, false);
        assert_eq!(backend.list().await.unwrap(), Vec::<String>::new());
    }

    #[tokio::test]
    async fn delete_removes_the_record_from_inventory() {
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
    async fn ordinary_record_remains_listed_and_retrievable_without_metadata() {
        let host = TestHost::new();
        let backend = YubikeyBackend::new(host.clone(), false);
        let entry_path = backend.entry_path("orphan");
        let key = derive_key(FAKE_HMAC_RESPONSE, "orphan").unwrap();
        let blob = encrypt_gcm_versioned(&key, "orphaned-secret", None).unwrap();
        host.files
            .lock()
            .unwrap()
            .insert(entry_path, blob.into_bytes());

        assert_eq!(backend.list().await.unwrap(), vec!["orphan"]);
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

    /// Regression test for issue #326: `delete()` never performs
    /// challenge-response — it only probes device presence
    /// (`require_device`) and unlinks the entry — so `get_capabilities` must
    /// not claim `Delete` is presence-enforced when `require_touch` is set.
    /// Before the fix, `presence_enforced_operations` was `None`, which
    /// `BackendCapabilities::enforces` treats as "every keyed operation is
    /// covered" — silently misrepresenting `delete` as touch-gated. This
    /// asserts the honest, operation-scoped contract: `Read` and `Store` are
    /// covered (both perform challenge-response), `Delete` is not.
    #[tokio::test]
    async fn get_capabilities_excludes_delete_from_presence_enforced_operations_issue_326() {
        let host = TestHost::new();
        let backend = YubikeyBackend::new(host, true);
        let caps = backend.get_capabilities().await.unwrap();

        assert!(caps.presence_per_use);
        assert_eq!(
            caps.presence_enforced_operations,
            Some(vec![PresenceOperation::Read, PresenceOperation::Store])
        );
        assert!(caps.enforces(PresenceOperation::Read));
        assert!(caps.enforces(PresenceOperation::Store));
        assert!(!caps.enforces(PresenceOperation::Delete));
    }

    /// Regression test for issue #326: a `--require-presence-per-use` delete
    /// must fail closed via `enforce_presence_requirement` rather than
    /// silently succeeding with no touch, now that `delete` is correctly
    /// excluded from `presence_enforced_operations`.
    #[tokio::test]
    async fn require_presence_per_use_delete_fails_closed_issue_326() {
        let host = TestHost::new();
        let backend = YubikeyBackend::new(host, true);

        let err = crate::vault::enforce_presence_requirement(
            &backend,
            PresenceOperation::Delete,
            Some(true),
        )
        .await
        .unwrap_err();

        assert!(matches!(err, VaultError::NotCapable { .. }));
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
