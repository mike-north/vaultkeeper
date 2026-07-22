//! Encrypted persistence for [`KeyManager`](super::KeyManager) state.
//!
//! Mirrors `packages/vaultkeeper/src/keys/storage.ts` byte-for-byte on disk:
//! key state is written under the host's config directory as two owner-only
//! (`0o600`) files, so a store written by one implementation is readable by
//! the other.
//!
//! - `keys.enc` — the AES-256-GCM envelope (`iv:authTag:ciphertext`, each part
//!   base64) of the JSON-serialized key state.
//! - `.keys.wrap` — the random 32-byte wrapping key that protects `keys.enc`.
//!
//! Persisting key material lets a JWE minted by one process be authorized by
//! a later process within the token's validity window: the `kid` a token
//! embeds still resolves to a known key after the minting process exits.
//! Without this, every process generated fresh keys, so a cached token always
//! failed authorization.
//!
//! All I/O goes through [`HostPlatform`] (never `std::fs` directly) so this
//! module works identically under wasm.

use std::path::Path;

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64ct::{Base64, Encoding};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::backend::HostPlatform;
use crate::errors::VaultError;
use crate::keys::types::{KeyMaterial, KeyStateSnapshot};
use crate::util::time;

const KEY_STATE_FILE: &str = "keys.enc";
/// Filename of the shared wrap key. `pub(crate)` so the `backend::signing_store`
/// module (backing [`crate::backend::FileBackend`]'s `SigningBackend` impl) can
/// HKDF-derive its own seal key from the same material (see that module's
/// docs) without duplicating the filename literal.
pub(crate) const KEY_WRAP_FILE: &str = ".keys.wrap";
const GCM_IV_BYTES: usize = 12;
const GCM_KEY_BYTES: usize = 32;
const GCM_TAG_BYTES: usize = 16;

/// Base64 (de)serialization for a `Vec<u8>` field, matching the TS
/// implementation's `Buffer.toString('base64')` / `Buffer.from(_, 'base64')`.
mod base64_key {
    use base64ct::{Base64, Encoding};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&Base64::encode_string(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(deserializer)?;
        Base64::decode_vec(&s).map_err(serde::de::Error::custom)
    }
}

/// On-disk JSON shape for a single key (raw bytes base64-encoded), matching
/// the TS `RawKeyMaterial`.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawKeyMaterial {
    id: String,
    #[serde(with = "base64_key")]
    key: Vec<u8>,
    created_at: String,
}

/// On-disk JSON shape for the whole key state, matching the TS `RawKeyState`.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawKeyState {
    version: u32,
    current: RawKeyMaterial,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    previous: Option<RawKeyMaterial>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    grace_period_expires_at: Option<u64>,
}

fn serialize_key(key: &KeyMaterial) -> RawKeyMaterial {
    RawKeyMaterial {
        id: key.id.clone(),
        key: key.key.clone(),
        created_at: epoch_secs_to_iso8601(key.created_at),
    }
}

/// Validate every field so a corrupt or truncated entry degrades to "no
/// persisted state" rather than yielding malformed key material (mirrors the
/// TS `deserializeKey` type guard).
fn deserialize_key(raw: RawKeyMaterial) -> Option<KeyMaterial> {
    if raw.id.is_empty() || raw.key.len() != GCM_KEY_BYTES {
        return None;
    }
    let created_at = iso8601_to_epoch_secs(&raw.created_at)?;
    Some(KeyMaterial {
        id: raw.id,
        key: raw.key,
        created_at,
    })
}

// ---------------------------------------------------------------------------
// AES-256-GCM envelope (iv:authTag:ciphertext, base64) — same shape as
// `backend::file` and the TS `util/at-rest.ts`, kept self-contained here so
// this module has no dependency on sibling modules under active parallel
// development.
// ---------------------------------------------------------------------------

fn encrypt_gcm(key: &[u8], plaintext: &str) -> Result<String, VaultError> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| VaultError::Other(format!("Invalid wrap key: {e}")))?;

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

/// Decrypt an `iv:authTag:ciphertext` envelope. Returns `None` on any
/// malformation or authentication failure — callers treat that as "no
/// recoverable state" rather than a hard error (a tampered envelope, or a
/// wrap key that no longer matches, is not distinguishable from corruption).
fn decrypt_gcm(key: &[u8], encoded: &str) -> Option<String> {
    let parts: Vec<&str> = encoded.split(':').collect();
    if parts.len() != 3 {
        return None;
    }
    let iv = Base64::decode_vec(parts[0]).ok()?;
    if iv.len() != GCM_IV_BYTES {
        return None;
    }
    let auth_tag = Base64::decode_vec(parts[1]).ok()?;
    if auth_tag.len() != GCM_TAG_BYTES {
        return None;
    }
    let ciphertext = Base64::decode_vec(parts[2]).ok()?;

    let cipher = Aes256Gcm::new_from_slice(key).ok()?;
    let nonce = Nonce::from_slice(&iv);

    let mut combined = ciphertext;
    combined.extend_from_slice(&auth_tag);

    let plaintext = cipher.decrypt(nonce, combined.as_slice()).ok()?;
    String::from_utf8(plaintext).ok()
}

/// Read the 32-byte wrapping key at `wrap_path`, generating and persisting a
/// fresh random one (mode `0o600`) when the file does not yet exist **or**
/// holds a value that is not exactly 32 bytes.
///
/// Regenerating on a wrong-length key is safe, not data loss: a wrapping key
/// of the wrong length cannot decrypt anything it previously encrypted, so
/// any ciphertext under a corrupt key is already unrecoverable.
///
/// A genuine read failure on an *existing, right-length-or-unreadable* key
/// file (e.g. permission denied) propagates unchanged as the typed
/// `VaultError` the host produced — only a confirmed-missing file triggers
/// regeneration, mirroring `FileBackend::get_or_create_key`.
pub(crate) async fn get_or_create_wrap_key(
    host: &dyn HostPlatform,
    wrap_path: &Path,
) -> Result<Vec<u8>, VaultError> {
    match host.read_file(wrap_path).await {
        Ok(data) if data.len() == GCM_KEY_BYTES => Ok(data),
        Ok(_) => generate_and_write_wrap_key(host, wrap_path).await,
        Err(read_err) => match host.file_exists(wrap_path).await {
            Ok(false) => generate_and_write_wrap_key(host, wrap_path).await,
            Ok(true) | Err(_) => Err(read_err),
        },
    }
}

async fn generate_and_write_wrap_key(
    host: &dyn HostPlatform,
    wrap_path: &Path,
) -> Result<Vec<u8>, VaultError> {
    let mut key = vec![0u8; GCM_KEY_BYTES];
    getrandom::fill(&mut key)
        .map_err(|e| VaultError::Other(format!("Failed to generate wrap key: {e}")))?;
    // Zeroize on a failed write too — this freshly generated key is real key
    // material, and an early `?` return would otherwise drop it un-wiped,
    // leaving it resident in memory after a failed persistence attempt.
    if let Err(err) = host.write_file(wrap_path, &key, 0o600).await {
        key.zeroize();
        return Err(err);
    }
    Ok(key)
}

/// Load persisted key state from the host's config directory, or `None` when
/// no valid state exists yet (first run, or an unreadable/corrupt `keys.enc`).
///
/// Mirrors the TS `loadKeyState`: any failure to read or decode `keys.enc`
/// degrades to "no state" rather than propagating — including permission
/// failures on that file — so a corrupt or inaccessible store never wedges
/// startup. A failure to read (or create) the wrapping key for a reason other
/// than "does not exist yet" (e.g. permission denied) is the one exception:
/// it propagates as the host's typed `VaultError`, matching the TS
/// `getOrCreateWrapKey` contract.
pub async fn load_key_state(
    host: &dyn HostPlatform,
) -> Result<Option<KeyStateSnapshot>, VaultError> {
    let state_path = host.config_dir().join(KEY_STATE_FILE);

    let envelope_bytes = match host.read_file(&state_path).await {
        Ok(bytes) => bytes,
        Err(_) => return Ok(None),
    };
    let Ok(envelope) = String::from_utf8(envelope_bytes) else {
        return Ok(None);
    };

    let wrap_path = host.config_dir().join(KEY_WRAP_FILE);
    let mut wrap_key = get_or_create_wrap_key(host, &wrap_path).await?;

    let json = decrypt_gcm(&wrap_key, &envelope);
    wrap_key.zeroize();
    let Some(json) = json else {
        return Ok(None);
    };

    let Ok(parsed) = serde_json::from_str::<RawKeyState>(&json) else {
        return Ok(None);
    };
    if parsed.version != 1 {
        return Ok(None);
    }

    let Some(current) = deserialize_key(parsed.current) else {
        return Ok(None);
    };

    let mut snapshot = KeyStateSnapshot {
        current,
        previous: None,
        grace_period_expires_at_ms: None,
    };

    if let (Some(prev_raw), Some(expires_at)) = (parsed.previous, parsed.grace_period_expires_at)
        && let Some(previous) = deserialize_key(prev_raw)
        // Only surface the previous key while its grace period is still
        // active; an expired grace period is equivalent to no previous key.
        && time::now_millis() < u128::from(expires_at)
    {
        snapshot.previous = Some(previous);
        snapshot.grace_period_expires_at_ms = Some(expires_at);
    }

    Ok(Some(snapshot))
}

/// Persist `snapshot` to the host's config directory. The state file and its
/// wrapping key are both written owner-only (`0o600`).
///
/// Uses write-to-temp-then-rename (via [`HostPlatform::rename_file`]) so a
/// concurrent [`load_key_state`] never observes a half-written envelope.
/// Every filesystem step (wrap-key read/write, temp write, rename) surfaces
/// the host's typed `VaultError::Filesystem` on failure rather than a generic
/// error, matching the `HostFilesystemError` contract at the wasm boundary.
pub async fn save_key_state(
    host: &dyn HostPlatform,
    snapshot: &KeyStateSnapshot,
) -> Result<(), VaultError> {
    let wrap_path = host.config_dir().join(KEY_WRAP_FILE);
    let mut wrap_key = get_or_create_wrap_key(host, &wrap_path).await?;

    let raw = RawKeyState {
        version: 1,
        current: serialize_key(&snapshot.current),
        previous: snapshot.previous.as_ref().map(serialize_key),
        grace_period_expires_at: match (&snapshot.previous, snapshot.grace_period_expires_at_ms) {
            (Some(_), Some(expiry)) => Some(expiry),
            _ => None,
        },
    };

    let json = serde_json::to_string(&raw)
        .map_err(|e| VaultError::Other(format!("Failed to serialize key state: {e}")))?;
    let envelope = encrypt_gcm(&wrap_key, &json);
    wrap_key.zeroize();
    let envelope = envelope?;

    let state_path = host.config_dir().join(KEY_STATE_FILE);
    let mut suffix = [0u8; 4];
    getrandom::fill(&mut suffix)
        .map_err(|e| VaultError::Other(format!("Failed to generate temp suffix: {e}")))?;
    let suffix_hex: String = suffix.iter().map(|b| format!("{b:02x}")).collect();
    let tmp_path = host
        .config_dir()
        .join(format!("{KEY_STATE_FILE}.{suffix_hex}.tmp"));

    host.write_file(&tmp_path, envelope.as_bytes(), 0o600)
        .await?;
    host.rename_file(&tmp_path, &state_path).await?;

    Ok(())
}

// ---------------------------------------------------------------------------
// ISO-8601 <-> epoch-seconds conversion
//
// `KeyMaterial::created_at` is epoch seconds (`u64`); the shared on-disk JSON
// stores it as an ISO-8601 UTC string (matching JavaScript's
// `Date.prototype.toISOString()`), since that's the wire format the TS
// implementation reads and writes. A single conversion doesn't justify a
// date/time crate dependency, so this uses Howard Hinnant's well-known
// `civil_from_days`/`days_from_civil` integer algorithm.
// ---------------------------------------------------------------------------

/// Convert epoch seconds to an ISO-8601 UTC string with millisecond precision
/// (e.g. `"2024-01-15T10:30:00.000Z"`). `created_at` only has second
/// precision, so the millisecond field is always `.000`.
fn epoch_secs_to_iso8601(epoch_secs: u64) -> String {
    let days = (epoch_secs / 86_400) as i64;
    let secs_of_day = epoch_secs % 86_400;
    let (year, month, day) = civil_from_days(days);
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.000Z")
}

/// Parse an ISO-8601 / RFC-3339 UTC timestamp (as produced by JS
/// `Date.prototype.toISOString()` or `epoch_secs_to_iso8601` above) into
/// epoch seconds, truncating any fractional seconds. Returns `None` for
/// anything that doesn't parse as a plausible timestamp; the caller treats
/// that as corrupt state.
fn iso8601_to_epoch_secs(s: &str) -> Option<u64> {
    let s = s.strip_suffix('Z')?;
    let (date, time) = s.split_once('T')?;

    let mut date_parts = date.split('-');
    let year: i64 = date_parts.next()?.parse().ok()?;
    let month: u32 = date_parts.next()?.parse().ok()?;
    let day: u32 = date_parts.next()?.parse().ok()?;
    if date_parts.next().is_some() {
        return None;
    }

    // Fractional seconds (if any) are ignored — created_at has second precision.
    let time = time.split('.').next()?;
    let mut time_parts = time.split(':');
    let hour: u64 = time_parts.next()?.parse().ok()?;
    let minute: u64 = time_parts.next()?.parse().ok()?;
    let second: u64 = time_parts.next()?.parse().ok()?;
    if time_parts.next().is_some() || hour >= 24 || minute >= 60 || second >= 60 {
        return None;
    }

    let days = days_from_civil(year, month, day)?;
    if days < 0 {
        // Pre-1970 timestamps are not representable in epoch seconds (u64).
        return None;
    }
    Some(days as u64 * 86_400 + hour * 3600 + minute * 60 + second)
}

/// Convert a day count since 1970-01-01 into a proleptic-Gregorian
/// `(year, month, day)`. See Howard Hinnant's "chrono-Compatible Low-Level
/// Date Algorithms" (<https://howardhinnant.github.io/date_algorithms.html>).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d)
}

/// Whether `y` is a leap year in the proleptic Gregorian calendar.
fn is_leap_year(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

/// Number of days in Gregorian calendar month `m` of year `y`. `m` must
/// already be known to be in `1..=12`; an out-of-range `m` returns `0`, which
/// makes any `d` fail the `d > days_in_month(y, m)` check in
/// [`days_from_civil`] rather than panicking.
fn days_in_month(y: i64, m: u32) -> u32 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap_year(y) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

/// Inverse of [`civil_from_days`].
///
/// Validates `d` against the actual number of days in month `m` of year `y`
/// (leap years included) — not just a blanket `1..=31` — so an impossible
/// calendar date (e.g. `2024-02-31`, or `2023-02-29` in a non-leap year) is
/// rejected as `None` rather than being silently normalized into some other
/// timestamp. A corrupt persisted `created_at` string must degrade to "no
/// recoverable state" (the contract [`iso8601_to_epoch_secs`] documents), not
/// resolve to a different date than whatever was actually on disk.
fn days_from_civil(y: i64, m: u32, d: u32) -> Option<i64> {
    if !(1..=12).contains(&m) || d < 1 || d > days_in_month(y, m) {
        return None;
    }
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64; // [0, 399]
    let doy = (153 * u64::from(if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + u64::from(d) - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    Some(era * 146_097 + doe as i64 - 719_468)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{ExecOptions, ExecOutput, Platform};
    use std::collections::{HashMap, HashSet};
    use std::path::PathBuf;
    use std::sync::Mutex;

    // -------------------------------------------------------------------
    // ISO-8601 conversion
    // -------------------------------------------------------------------

    #[test]
    fn iso8601_round_trip_epoch_zero() {
        assert_eq!(epoch_secs_to_iso8601(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(iso8601_to_epoch_secs("1970-01-01T00:00:00.000Z"), Some(0));
    }

    #[test]
    fn iso8601_round_trip_known_timestamp() {
        // 2024-01-15T10:30:00Z, verified against the shared fixed test date
        // used throughout this repo's TS test suite.
        let secs = 1_705_314_600u64;
        assert_eq!(epoch_secs_to_iso8601(secs), "2024-01-15T10:30:00.000Z");
        assert_eq!(
            iso8601_to_epoch_secs("2024-01-15T10:30:00.000Z"),
            Some(secs)
        );
    }

    #[test]
    fn iso8601_parses_js_millisecond_fraction() {
        // JS `Date.toISOString()` always emits milliseconds; a non-zero
        // fraction must still parse (truncated to whole seconds).
        assert_eq!(
            iso8601_to_epoch_secs("2024-01-15T10:30:00.123Z"),
            Some(1_705_314_600)
        );
    }

    #[test]
    fn iso8601_rejects_malformed_input() {
        assert_eq!(iso8601_to_epoch_secs("not-a-date"), None);
        assert_eq!(iso8601_to_epoch_secs("2024-01-15T10:30:00.000"), None); // missing Z
        assert_eq!(iso8601_to_epoch_secs("2024-13-01T00:00:00.000Z"), None); // month 13
        assert_eq!(iso8601_to_epoch_secs("2024-01-15T25:00:00.000Z"), None); // hour 25
    }

    /// Regression test: `days_from_civil` previously only bounded the day
    /// component to `1..=31`, so an impossible calendar date like
    /// `2024-02-31` normalized into whatever date the underlying arithmetic
    /// happened to produce instead of being rejected. A corrupt persisted
    /// `created_at` must degrade to `None` ("no recoverable state"), not
    /// silently resolve to a different timestamp than what was on disk.
    #[test]
    fn iso8601_rejects_impossible_calendar_dates() {
        assert_eq!(iso8601_to_epoch_secs("2024-02-31T00:00:00.000Z"), None); // Feb never has 31 days
        assert_eq!(iso8601_to_epoch_secs("2023-02-29T00:00:00.000Z"), None); // 2023 is not a leap year
        assert_eq!(iso8601_to_epoch_secs("2024-04-31T00:00:00.000Z"), None); // April has 30 days
        assert_eq!(iso8601_to_epoch_secs("2024-01-00T00:00:00.000Z"), None); // day 0
    }

    /// The leap-day case the above test's non-leap-year rejection is a
    /// counterpart to: `2024-02-29` is a real date and must still parse.
    #[test]
    fn iso8601_accepts_leap_day() {
        assert!(iso8601_to_epoch_secs("2024-02-29T00:00:00.000Z").is_some());
    }

    // -------------------------------------------------------------------
    // Test host double (in-memory, self-contained to this module).
    // -------------------------------------------------------------------

    struct TestHost {
        files: Mutex<HashMap<PathBuf, Vec<u8>>>,
        config_dir: PathBuf,
        deny_read: Mutex<HashSet<PathBuf>>,
    }

    impl TestHost {
        fn new() -> Self {
            Self {
                files: Mutex::new(HashMap::new()),
                config_dir: PathBuf::from("/test/config"),
                deny_read: Mutex::new(HashSet::new()),
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
        async fn list_dir(&self, _path: &Path) -> Result<Vec<String>, VaultError> {
            Ok(Vec::new())
        }
        fn platform(&self) -> Platform {
            Platform::Linux
        }
        fn config_dir(&self) -> &Path {
            &self.config_dir
        }
    }

    fn make_key(id: &str, byte: u8, created_at: u64) -> KeyMaterial {
        KeyMaterial {
            id: id.to_string(),
            key: vec![byte; GCM_KEY_BYTES],
            created_at,
        }
    }

    // -------------------------------------------------------------------
    // Round trip
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn save_then_load_round_trips_current_key() {
        let host = TestHost::new();
        let current = make_key("k-1-aaaa", 0x11, 1_705_314_600);
        save_key_state(
            &host,
            &KeyStateSnapshot {
                current: current.clone(),
                previous: None,
                grace_period_expires_at_ms: None,
            },
        )
        .await
        .unwrap();

        let loaded = load_key_state(&host).await.unwrap().unwrap();
        assert_eq!(loaded.current.id, current.id);
        assert_eq!(loaded.current.key, current.key);
        assert_eq!(loaded.current.created_at, current.created_at);
        assert!(loaded.previous.is_none());
    }

    #[tokio::test]
    async fn load_returns_none_when_no_state_file_exists() {
        let host = TestHost::new();
        assert!(load_key_state(&host).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn save_then_load_round_trips_previous_key_within_grace_period() {
        let host = TestHost::new();
        let expires_at = (time::now_millis() + 60_000) as u64;
        save_key_state(
            &host,
            &KeyStateSnapshot {
                current: make_key("k-2-bbbb", 0x22, 1_705_314_600),
                previous: Some(make_key("k-1-aaaa", 0x11, 1_705_300_000)),
                grace_period_expires_at_ms: Some(expires_at),
            },
        )
        .await
        .unwrap();

        let loaded = load_key_state(&host).await.unwrap().unwrap();
        assert_eq!(
            loaded.previous.as_ref().map(|k| k.id.as_str()),
            Some("k-1-aaaa")
        );
        assert_eq!(loaded.grace_period_expires_at_ms, Some(expires_at));
    }

    #[tokio::test]
    async fn load_drops_expired_previous_key() {
        let host = TestHost::new();
        let expires_at = (time::now_millis().saturating_sub(1)) as u64; // already elapsed
        save_key_state(
            &host,
            &KeyStateSnapshot {
                current: make_key("k-2-bbbb", 0x22, 1_705_314_600),
                previous: Some(make_key("k-1-aaaa", 0x11, 1_705_300_000)),
                grace_period_expires_at_ms: Some(expires_at),
            },
        )
        .await
        .unwrap();

        let loaded = load_key_state(&host).await.unwrap().unwrap();
        assert!(loaded.previous.is_none());
        assert!(loaded.grace_period_expires_at_ms.is_none());
    }

    // -------------------------------------------------------------------
    // Encryption / permissions
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn state_file_is_encrypted_not_plaintext() {
        let host = TestHost::new();
        let current = make_key("k-secret-id", 0x33, 1_705_314_600);
        save_key_state(
            &host,
            &KeyStateSnapshot {
                current: current.clone(),
                previous: None,
                grace_period_expires_at_ms: None,
            },
        )
        .await
        .unwrap();

        let raw = host
            .read_file(&host.config_dir().join(KEY_STATE_FILE))
            .await
            .unwrap();
        let raw = String::from_utf8(raw).unwrap();
        assert!(!raw.contains("k-secret-id"));
        assert!(!raw.contains(&Base64::encode_string(&current.key)));
        assert_eq!(raw.split(':').count(), 3);
    }

    #[tokio::test]
    async fn state_and_wrap_files_written_owner_only() {
        let host = TestHost::new();
        save_key_state(
            &host,
            &KeyStateSnapshot {
                current: make_key("k-1-aaaa", 0x11, 1_705_314_600),
                previous: None,
                grace_period_expires_at_ms: None,
            },
        )
        .await
        .unwrap();

        // `write_file(path, content, mode)` is called with 0o600 for both
        // files; the in-memory TestHost doesn't model mode bits, so this is
        // asserted end-to-end against the real NativeHostPlatform in
        // crates/vaultkeeper-cli's integration tests instead. Here we assert
        // only that both files were actually written.
        assert!(
            host.file_exists(&host.config_dir().join(KEY_STATE_FILE))
                .await
                .unwrap()
        );
        assert!(
            host.file_exists(&host.config_dir().join(KEY_WRAP_FILE))
                .await
                .unwrap()
        );
    }

    // -------------------------------------------------------------------
    // AC6 — negative tests: corrupt envelope, missing wrap file, truncated
    // store must degrade to typed results, never panic.
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn corrupt_envelope_degrades_to_no_state() {
        let host = TestHost::new();
        save_key_state(
            &host,
            &KeyStateSnapshot {
                current: make_key("k-1-aaaa", 0x11, 1_705_314_600),
                previous: None,
                grace_period_expires_at_ms: None,
            },
        )
        .await
        .unwrap();

        // Tamper with the ciphertext so AES-GCM authentication fails.
        let state_path = host.config_dir().join(KEY_STATE_FILE);
        let envelope = String::from_utf8(host.read_file(&state_path).await.unwrap()).unwrap();
        let parts: Vec<&str> = envelope.split(':').collect();
        let mut ct = Base64::decode_vec(parts[2]).unwrap();
        if !ct.is_empty() {
            ct[0] ^= 0xff;
        }
        let tampered = format!("{}:{}:{}", parts[0], parts[1], Base64::encode_string(&ct));
        host.write_file(&state_path, tampered.as_bytes(), 0o600)
            .await
            .unwrap();

        assert!(load_key_state(&host).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn truncated_store_degrades_to_no_state() {
        let host = TestHost::new();
        let state_path = host.config_dir().join(KEY_STATE_FILE);
        host.write_file(&state_path, b"not-an-envelope", 0o600)
            .await
            .unwrap();

        assert!(load_key_state(&host).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn missing_wrap_file_degrades_to_no_state_and_regenerates() {
        let host = TestHost::new();
        save_key_state(
            &host,
            &KeyStateSnapshot {
                current: make_key("k-1-aaaa", 0x11, 1_705_314_600),
                previous: None,
                grace_period_expires_at_ms: None,
            },
        )
        .await
        .unwrap();

        // Delete the wrap key; keys.enc is now unrecoverable (encrypted under
        // a key we no longer have), matching a lost/rotated wrap key.
        let wrap_path = host.config_dir().join(KEY_WRAP_FILE);
        host.delete_file(&wrap_path).await.unwrap();

        assert!(load_key_state(&host).await.unwrap().is_none());
        // A fresh wrap key was generated in its place (not left missing), so
        // a subsequent save works normally.
        assert!(host.file_exists(&wrap_path).await.unwrap());

        let fresh = make_key("k-new-bbbb", 0x22, 1_705_314_600);
        save_key_state(
            &host,
            &KeyStateSnapshot {
                current: fresh.clone(),
                previous: None,
                grace_period_expires_at_ms: None,
            },
        )
        .await
        .unwrap();
        let loaded = load_key_state(&host).await.unwrap().unwrap();
        assert_eq!(loaded.current.id, "k-new-bbbb");
    }

    #[tokio::test]
    async fn wrong_length_wrap_key_is_regenerated_not_a_panic() {
        let host = TestHost::new();
        save_key_state(
            &host,
            &KeyStateSnapshot {
                current: make_key("k-old-aaaa", 0x11, 1_705_314_600),
                previous: None,
                grace_period_expires_at_ms: None,
            },
        )
        .await
        .unwrap();

        let wrap_path = host.config_dir().join(KEY_WRAP_FILE);
        host.write_file(&wrap_path, &[0xab; 7], 0o600)
            .await
            .unwrap();

        assert!(load_key_state(&host).await.unwrap().is_none());

        let fresh = make_key("k-new-bbbb", 0x22, 1_705_314_600);
        save_key_state(
            &host,
            &KeyStateSnapshot {
                current: fresh,
                previous: None,
                grace_period_expires_at_ms: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(
            host.read_file(&wrap_path).await.unwrap().len(),
            GCM_KEY_BYTES
        );
    }

    /// AC4: a genuine read failure (not "missing") on an existing wrap key
    /// must propagate as the host's typed `VaultError::Filesystem`, not be
    /// swallowed or panic.
    #[tokio::test]
    async fn wrap_key_permission_failure_surfaces_as_typed_filesystem_error() {
        let host = TestHost::new();
        // Seed a valid-looking wrap key, then deny reads to it.
        let wrap_path = host.config_dir().join(KEY_WRAP_FILE);
        host.write_file(&wrap_path, &[0u8; GCM_KEY_BYTES], 0o600)
            .await
            .unwrap();
        host.deny_read.lock().unwrap().insert(wrap_path.clone());

        let err = save_key_state(
            &host,
            &KeyStateSnapshot {
                current: make_key("k-1-aaaa", 0x11, 1_705_314_600),
                previous: None,
                grace_period_expires_at_ms: None,
            },
        )
        .await
        .unwrap_err();

        match err {
            VaultError::Filesystem {
                path, permission, ..
            } => {
                assert_eq!(path, wrap_path.display().to_string());
                assert_eq!(permission, "read");
            }
            other => panic!("expected VaultError::Filesystem, got {other:?}"),
        }
    }

    #[test]
    fn deserialize_key_rejects_wrong_length_key_bytes() {
        let raw = RawKeyMaterial {
            id: "k-1".to_string(),
            key: vec![0u8; 7],
            created_at: "2024-01-15T10:30:00.000Z".to_string(),
        };
        assert!(deserialize_key(raw).is_none());
    }

    #[test]
    fn deserialize_key_rejects_empty_id() {
        let raw = RawKeyMaterial {
            id: String::new(),
            key: vec![0u8; GCM_KEY_BYTES],
            created_at: "2024-01-15T10:30:00.000Z".to_string(),
        };
        assert!(deserialize_key(raw).is_none());
    }

    // -------------------------------------------------------------------
    // AC2 — cross-implementation compatibility fixture.
    //
    // These bytes were produced by the TS implementation
    // (`packages/vaultkeeper/src/keys/storage.ts`) calling `saveKeyState`
    // with the exact `KeyMaterial` asserted below (id
    // `k-fixture-1705314600000-abcd`, key bytes `0x10..=0x2f`, createdAt
    // `2024-01-15T10:30:00.000Z`). To regenerate after a deliberate format
    // change, run a script that imports `saveKeyState` from that module with
    // the same fixed `KeyMaterial` and overwrite the two files under
    // `crates/vaultkeeper-core/tests/fixtures/ts-written-keystate/`.
    // -------------------------------------------------------------------

    const TS_FIXTURE_KEYS_ENC: &[u8] =
        include_bytes!("../../tests/fixtures/ts-written-keystate/keys.enc");
    const TS_FIXTURE_KEYS_WRAP: &[u8] =
        include_bytes!("../../tests/fixtures/ts-written-keystate/.keys.wrap");

    #[tokio::test]
    async fn ac2_hydrates_a_ts_written_fixture() {
        let host = TestHost::new();
        host.files.lock().unwrap().insert(
            host.config_dir().join(KEY_STATE_FILE),
            TS_FIXTURE_KEYS_ENC.to_vec(),
        );
        host.files.lock().unwrap().insert(
            host.config_dir().join(KEY_WRAP_FILE),
            TS_FIXTURE_KEYS_WRAP.to_vec(),
        );

        let loaded = load_key_state(&host).await.unwrap().unwrap();
        assert_eq!(loaded.current.id, "k-fixture-1705314600000-abcd");
        assert_eq!(loaded.current.key, (0x10u8..=0x2f).collect::<Vec<u8>>());
        assert_eq!(loaded.current.created_at, 1_705_314_600);
        assert!(loaded.previous.is_none());
    }
}
