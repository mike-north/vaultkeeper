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

use std::collections::HashMap;
use std::path::Path;

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64ct::{Base64, Encoding};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::backend::HostPlatform;
use crate::errors::VaultError;
use crate::keys::types::{JtiEntry, KeyMaterial, KeyStateSnapshot, RevocationState};
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
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct RawKeyMaterial {
    id: String,
    #[serde(with = "base64_key")]
    key: Vec<u8>,
    created_at: String,
}

/// On-disk JSON shape for a single revoked-jti entry, matching
/// [`JtiEntry`](crate::keys::types::JtiEntry).
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct RawJtiEntry {
    jti: String,
    exp: u64,
}

impl From<RawJtiEntry> for JtiEntry {
    fn from(raw: RawJtiEntry) -> Self {
        JtiEntry {
            jti: raw.jti,
            exp: raw.exp,
        }
    }
}

impl From<&JtiEntry> for RawJtiEntry {
    fn from(entry: &JtiEntry) -> Self {
        RawJtiEntry {
            jti: entry.jti.clone(),
            exp: entry.exp,
        }
    }
}

/// On-disk JSON shape for the whole key state, matching the TS `RawKeyState`.
///
/// `rev_state_gen`/`jti`/`key_generations` are the two-axis lease revocation
/// store (issue #298) — co-located in this same encrypted envelope rather
/// than a new file; see the module doc and
/// [`RevocationState`](crate::keys::types::RevocationState) for the design.
/// `#[serde(default)]` on all three keeps this format readable by a key
/// state written before #298 (no revocation activity yet is exactly the
/// default: generation 0, no revocations).
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawKeyState {
    version: u32,
    current: RawKeyMaterial,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    previous: Option<RawKeyMaterial>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    grace_period_expires_at: Option<u64>,
    #[serde(default)]
    rev_state_gen: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    jti: Vec<RawJtiEntry>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    key_generations: HashMap<String, u64>,
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

/// Outcome of attempting to decode the persisted `keys.enc` envelope.
/// Distinguishes "nothing was ever persisted" ([`RawLoad::Absent`]) from
/// "something is persisted but did not authenticate/parse"
/// ([`RawLoad::Corrupt`]) — [`load_key_state`] collapses both into `None`
/// (safe: a caller just regenerates key material), but the revocation-aware
/// loaders below must not make that same collapse, since silently treating
/// "corrupt" as "no revocations yet" would be a revocation bypass.
enum RawLoad {
    Absent,
    Corrupt,
    Present(Box<RawKeyState>),
}

/// Read and decode `keys.enc` into its raw on-disk shape, without validating
/// individual key-material fields (that is [`deserialize_key`]'s job, used
/// only by [`load_key_state`]). Shared by every loader in this module so the
/// envelope-decode logic (read, base64/UTF-8, AES-GCM auth, JSON parse,
/// version check) lives in exactly one place.
async fn try_load_raw(host: &dyn HostPlatform) -> Result<RawLoad, VaultError> {
    let state_path = host.config_dir().join(KEY_STATE_FILE);

    // Same classification `get_or_create_wrap_key` applies to the wrap file:
    // a read failure only means "absent" when the file genuinely doesn't
    // exist. A read failure on a file that does exist (permission denied, a
    // transient I/O error) is not "nothing was ever persisted" — collapsing
    // it into `Absent` would make every downstream caller treat an
    // inaccessible-but-present store as if it were a fresh install (silently
    // regenerating keys in `load_key_state`'s caller, or worse, treating a
    // revocation store we simply couldn't read as "no revocations" if this
    // were ever collapsed further). Propagate it as the host's typed error
    // instead.
    let envelope_bytes = match host.read_file(&state_path).await {
        Ok(bytes) => bytes,
        Err(read_err) => match host.file_exists(&state_path).await {
            Ok(false) => return Ok(RawLoad::Absent),
            Ok(true) | Err(_) => return Err(read_err),
        },
    };
    let Ok(envelope) = String::from_utf8(envelope_bytes) else {
        return Ok(RawLoad::Corrupt);
    };

    let wrap_path = host.config_dir().join(KEY_WRAP_FILE);
    let mut wrap_key = get_or_create_wrap_key(host, &wrap_path).await?;

    let json = decrypt_gcm(&wrap_key, &envelope);
    wrap_key.zeroize();
    let Some(json) = json else {
        return Ok(RawLoad::Corrupt);
    };

    let Ok(parsed) = serde_json::from_str::<RawKeyState>(&json) else {
        return Ok(RawLoad::Corrupt);
    };
    if parsed.version != 1 {
        return Ok(RawLoad::Corrupt);
    }

    Ok(RawLoad::Present(Box::new(parsed)))
}

fn revocation_from_raw(parsed: &RawKeyState) -> RevocationState {
    RevocationState {
        rev_state_gen: parsed.rev_state_gen,
        jti: parsed.jti.iter().cloned().map(Into::into).collect(),
        key_generations: parsed.key_generations.clone(),
    }
}

/// Load persisted key state from the host's config directory, or `None` when
/// no valid state exists yet (first run, or an unreadable/corrupt `keys.enc`).
///
/// Mirrors the TS `loadKeyState` for a genuinely missing or corrupt/tampered
/// `keys.enc`: both degrade to "no state" rather than propagating, so a
/// fresh install or a damaged store never wedges startup. This intentionally
/// diverges from the TS implementation (which collapses *every* read
/// failure, including permission errors, into "absent") on one point: a read
/// failure on a `keys.enc` that does exist (e.g. permission denied) is not
/// "nothing was ever persisted", so it propagates as the host's typed
/// `VaultError` instead of being swallowed — the same classification
/// `get_or_create_wrap_key` already applies to the wrap file. A failure to
/// read (or create) the wrapping key for a reason other than "does not exist
/// yet" propagates the same way, matching the TS `getOrCreateWrapKey`
/// contract.
///
/// This is a key-*material* loader only — it does not return the co-located
/// revocation state (see [`load_revocation_for_validation`] and
/// [`mutate_revocation_state`] for that, which have a deliberately different,
/// fail-closed contract).
pub async fn load_key_state(
    host: &dyn HostPlatform,
) -> Result<Option<KeyStateSnapshot>, VaultError> {
    let parsed = match try_load_raw(host).await? {
        RawLoad::Present(parsed) => parsed,
        RawLoad::Absent | RawLoad::Corrupt => return Ok(None),
    };

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

/// Load the persisted revocation state for **lease validation** (issue #298).
/// Deliberately a different contract from [`load_key_state`]'s "degrade
/// silently to no state": silence there is safe (the caller just
/// mints/regenerates a key), but silence here would be a revocation bypass —
/// "absence is not empty". Every failure mode a lease validator must treat
/// identically — a missing envelope, a broken GCM tag / corrupt payload
/// (modification), or a `revStateGen` lower than `min_rev_state_gen`
/// (rollback/replay) — is surfaced as a [`VaultError::TokenRevoked`] with a
/// message naming which one, rather than collapsed into `None` the way
/// [`load_key_state`] collapses it. Reusing `TokenRevoked` (instead of a new
/// error-taxonomy variant) is deliberate: the safe answer to "can this
/// revocation store be trusted?" being "no" *is* "treat the lease as
/// revoked" — see this crate's error-taxonomy docs for why a new variant
/// would also require WASM/TS parity plumbing this PR does not otherwise
/// need.
///
/// `min_rev_state_gen` is the highest `revStateGen` the caller has itself
/// observed so far in this process's lifetime (`0` on a fresh process/first
/// call) — the caller is the anti-rollback anchor, not this function; see
/// [`crate::vault::VaultKeeper::validate_lease_revocation`].
///
/// **Honest integrity limit** (see also the `keys.enc` module doc): an
/// attacker who can read the vault key can forge a valid GCM tag and a
/// self-consistent `revStateGen`, so this does not defend against full
/// same-UID compromise. It does defend against modification by anything that
/// cannot read the vault key, accidental corruption, partial writes, and
/// off-box manipulation of a synced/backed-up config directory.
pub async fn load_revocation_for_validation(
    host: &dyn HostPlatform,
    min_rev_state_gen: u64,
) -> Result<RevocationState, VaultError> {
    let parsed = match try_load_raw(host).await? {
        RawLoad::Present(parsed) => parsed,
        RawLoad::Absent => {
            return Err(VaultError::TokenRevoked {
                message: "Lease refused: no revocation store is persisted (keys.enc is \
                          missing). A signing lease requires a persisted revocation store to \
                          validate against; its absence fails closed rather than being treated \
                          as \"nothing has ever been revoked\". Recovery: restore keys.enc and \
                          .keys.wrap from backup."
                    .to_string(),
            });
        }
        RawLoad::Corrupt => {
            return Err(VaultError::TokenRevoked {
                message: "Lease refused: the revocation store (keys.enc) failed to \
                          authenticate or parse — modified, corrupted, truncated, or wrapped \
                          under a different key. Recovery: restore keys.enc and .keys.wrap \
                          from backup."
                    .to_string(),
            });
        }
    };

    if parsed.rev_state_gen < min_rev_state_gen {
        return Err(VaultError::TokenRevoked {
            message: format!(
                "Lease refused: revocation store rollback detected (revStateGen {} is lower \
                 than the {min_rev_state_gen} this process has already observed). Recovery: \
                 restore the latest keys.enc, or re-apply every revocation issued since the \
                 restored copy was taken.",
                parsed.rev_state_gen
            ),
        });
    }

    Ok(revocation_from_raw(&parsed))
}

// ---------------------------------------------------------------------------
// Cross-process advisory lock (issue #322) — built entirely on
// [`HostPlatform::try_create_lock_file`]/[`HostPlatform::delete_file`], so it
// works identically under wasm on any host that opts in, exactly like the
// rest of this module.
//
// A single lock guards the *entire* revocation-state read-modify-write
// surface — both [`mutate_revocation_state`] and [`save_key_state`] acquire
// it — because the race issue #322 exists to fix is specifically a
// `rotateKey`/`revokeKey` (`save_key_state`) call overlapping a
// `session revoke` (`mutate_revocation_state`) call, not just two calls to
// the same function.
// ---------------------------------------------------------------------------

/// Filename of the advisory lock file, co-located with `keys.enc` in the same
/// config directory.
const REVOCATION_LOCK_FILE: &str = "keys.enc.lock";

/// How long (ms) an unrenewed lock file is treated as abandoned and eligible
/// for takeover by another acquirer — recovers a lock left behind by a
/// process that crashed or panicked mid-critical-section, at the cost of a
/// bounded window during which a still-alive-but-unusually-slow holder could
/// theoretically be pre-empted. 30s is generously longer than this module's
/// own critical sections (a handful of small file I/O calls), so a
/// legitimate holder is never actually still running when this fires in
/// practice.
///
/// Staleness is judged against a wall-clock (`SystemTime`/`Date.now()`)
/// epoch-ms marker, not a monotonic clock, because the marker must be
/// meaningful when read back by a *different* OS process from disk —
/// monotonic clocks have no cross-process shared origin. The tradeoff: a
/// backward wall-clock step (NTP correction, manual clock change) can make an
/// abandoned lock look artificially fresh for up to the size of the step,
/// delaying takeover. This is self-healing, not a stuck state — once real
/// time passes `LOCK_STALE_AFTER_MS` again, the existing bounded retry
/// (`LOCK_MAX_ATTEMPTS`) takes the lock over exactly as it would have
/// without the clock step.
const LOCK_STALE_AFTER_MS: u128 = 30_000;

/// Bounded retry count for lock acquisition. Each attempt either succeeds,
/// hits genuine contention from a still-live holder (retried after a brief
/// pause), or hits a stale lock (taken over immediately, then retried) — this
/// bounds the total wait so acquisition fails loudly rather than looping
/// forever if something keeps re-contending.
const LOCK_MAX_ATTEMPTS: u32 = 50;

/// RAII guard for the revocation-state lock, returned by [`acquire_lock`].
///
/// Release the lock via the explicit async [`LockGuard::release`] — every
/// caller in this module goes through [`with_revocation_lock`], which
/// guarantees `release()` runs on **every** return from the wrapped critical
/// section, success or error (issue #322 AC: "guard releases on the
/// error/early-return path"). `Drop` exists as RAII discipline and a safety
/// net, but Rust has no async `Drop`: it cannot itself make the
/// [`HostPlatform::delete_file`] call release needs, so a guard that reaches
/// `Drop` without having been released (only possible if the critical
/// section panics — every non-panicking path goes through
/// `with_revocation_lock`) cannot delete the lock file from that synchronous
/// callback. That is not silently unsafe: a lock abandoned this way is
/// recovered by the *next* acquirer's stale-lock takeover in [`acquire_lock`]
/// (see `LOCK_STALE_AFTER_MS`), not by this `Drop` impl — see
/// `stale_lock_left_by_a_panicked_holder_is_taken_over` below for the test
/// that proves that recovery path, and
/// `lock_is_released_immediately_when_the_critical_section_errors` for the
/// normal-path release guarantee `Drop` is *not* standing in for.
struct LockGuard<'a> {
    host: &'a dyn HostPlatform,
    lock_path: std::path::PathBuf,
    /// `true` only when this guard actually holds a lock created via
    /// [`HostPlatform::try_create_lock_file`] — `false` when the host
    /// doesn't support locking (the trait's fail-closed default), in which
    /// case there is nothing to release.
    held: bool,
    released: bool,
}

impl LockGuard<'_> {
    async fn release(mut self) {
        if self.held && !self.released {
            // Best-effort: a failure to delete an already-released lock file
            // (e.g. a concurrent stale-lock takeover already removed it) is
            // not itself an error the caller needs to see — the lock is
            // gone either way.
            let _ = self.host.delete_file(&self.lock_path).await;
        }
        self.released = true;
    }
}

impl Drop for LockGuard<'_> {
    fn drop(&mut self) {
        // See the struct doc comment: this is a safety net for the one path
        // that can reach here without `release()` having run — a panic
        // inside the critical section `with_revocation_lock` wraps. Any
        // other path reaching `Drop` unreleased is a bug in this module
        // (a future change that forgot to route through
        // `with_revocation_lock`), so surface it loudly in debug builds
        // rather than let it silently rely on stale-lock takeover.
        if self.held && !self.released && !std::thread::panicking() {
            debug_assert!(
                false,
                "LockGuard for {} dropped without release() outside of a panic — route every \
                 acquisition through with_revocation_lock",
                self.lock_path.display()
            );
        }
    }
}

/// Attempt to take over `lock_path` if the lock file currently there is
/// older than [`LOCK_STALE_AFTER_MS`]. A malformed or unreadable marker is
/// treated as *not* stale (never taken over) — this only ever recovers a
/// lock this module itself created (whose content is always a plain decimal
/// millisecond timestamp), never guesses at an unrecognized file.
///
/// **TOCTOU note** (issue #322 review): a naive "read, decide stale, delete"
/// sequence has a real race, not just a theoretical one — a *second*
/// contender can independently observe the same stale marker, delete it, and
/// successfully recreate the lock (a legitimate fresh acquisition) in the
/// gap between this function's read and its delete. An unconditional delete
/// at that point would tear down that contender's brand-new, valid lock
/// (not the stale one this function decided to reap), and the file's mere
/// absence afterward would let a *third* party acquire it too — two holders
/// believing they exclusively hold the lock simultaneously, exactly the bug
/// this whole mechanism exists to prevent. This function closes that window
/// by re-reading the marker immediately before deleting and only deleting
/// when its content is byte-identical to what was originally observed as
/// stale — a marker recreated in between (by definition carrying a fresh,
/// non-stale timestamp) never matches, so it is left alone. This does not
/// require a new `HostPlatform` primitive (no atomic compare-and-delete
/// exists in this trait, nor in the POSIX/Windows filesystem calls it maps
/// to) — it shrinks the race to the residual gap between the confirmation
/// read and the delete call directly below it, which is now just two
/// sequential host calls with nothing else in between, rather than the
/// entire staleness-check-plus-earlier-read window. See
/// `take_over_if_stale_never_deletes_a_lock_recreated_between_its_reads` for
/// the regression test that exercises exactly this interleaving.
async fn take_over_if_stale(host: &dyn HostPlatform, lock_path: &Path) {
    let Ok(existing) = host.read_file(lock_path).await else {
        return;
    };
    let Ok(existing_str) = String::from_utf8(existing.clone()) else {
        return;
    };
    let Ok(created_at_ms) = existing_str.trim().parse::<u128>() else {
        return;
    };
    if time::now_millis().saturating_sub(created_at_ms) <= LOCK_STALE_AFTER_MS {
        return;
    }

    // Re-verify immediately before deleting — see the doc comment above.
    let Ok(current) = host.read_file(lock_path).await else {
        // Already gone: a concurrent takeover or a normal release beat us
        // to it. Nothing to delete.
        return;
    };
    if current != existing {
        // The marker changed since we decided it was stale — a concurrent
        // acquirer already took over (or the original holder released and
        // someone else acquired). This is no longer the stale lock we
        // observed, so it must not be deleted.
        return;
    }

    // Best-effort: if a concurrent release/takeover removes it in the
    // instant between this check and the delete call itself, this simply
    // no-ops — there is nothing left to distinguish at that point.
    let _ = host.delete_file(lock_path).await;
}

/// How long [`pause_before_retry`] waits between contention retries. Only
/// meaningful (and only referenced) on the non-wasm32 implementation below
/// — the wasm32 one never pauses (see its doc comment) — so this is
/// `cfg`-gated the same way to avoid an unused-constant warning on that
/// target.
#[cfg(not(target_arch = "wasm32"))]
const RETRY_PAUSE_MS: u64 = 2;

/// Pause briefly between lock-acquisition retries, without blocking the
/// calling OS/executor thread.
///
/// This crate is platform-agnostic (native and wasm32 both build it) and
/// deliberately does not take a real async-runtime dependency (e.g. `tokio`
/// is a dev-only dependency here — see `Cargo.toml`) so it stays usable from
/// any host's own executor, including the WASM/JS bridge's. That rules out
/// `tokio::time::sleep`. It also rules back in `std::thread::sleep`, which
/// blocks whatever OS thread happens to be polling this future — on
/// `NativeHostPlatform`, that thread is a `tokio` worker shared with every
/// other task the CLI process is running, so a blocking sleep there stalls
/// unrelated work for the pause's duration, not just this lock's contention
/// loop.
///
/// # Native: a genuinely non-blocking async sleep
///
/// Spawns a short-lived helper OS thread that sleeps and then wakes this
/// future's `Waker`, so the polling task returns `Pending` immediately and
/// the executor is free to run other work in the meantime — a small
/// hand-rolled `Future` rather than a runtime-provided timer, since no async
/// runtime is a real dependency of this crate. This only ever runs on actual
/// lock contention (bounded by [`LOCK_MAX_ATTEMPTS`]), so the per-attempt
/// cost of a helper thread is acceptable.
///
/// # WASM: no pause at all
///
/// `std::thread::spawn` is unavailable on `wasm32-unknown-unknown` (no OS
/// threads), and there is no portable non-blocking sleep primitive in this
/// crate's dependency set for that target either. This only matters once a
/// wasm host actually implements `try_create_lock_file` contention (no wasm
/// host does yet — see that trait method's doc comment), so retrying
/// immediately with no pause there is harmless today; a future wasm host
/// that adds real lock contention should route its pause through a
/// `HostPlatform`-supplied primitive (e.g. the JS event loop's
/// `setTimeout`) instead of extending this function.
#[cfg(not(target_arch = "wasm32"))]
async fn pause_before_retry() {
    use std::sync::{Arc, Mutex};
    use std::task::Waker;

    struct SleepState {
        done: bool,
        waker: Option<Waker>,
    }

    struct Sleep(Arc<Mutex<SleepState>>);

    impl std::future::Future for Sleep {
        type Output = ();

        fn poll(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<()> {
            let mut state = self
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if state.done {
                std::task::Poll::Ready(())
            } else {
                state.waker = Some(cx.waker().clone());
                std::task::Poll::Pending
            }
        }
    }

    let state = Arc::new(Mutex::new(SleepState {
        done: false,
        waker: None,
    }));
    let thread_state = Arc::clone(&state);
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(RETRY_PAUSE_MS));
        let mut state = thread_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.done = true;
        if let Some(waker) = state.waker.take() {
            waker.wake();
        }
    });

    Sleep(state).await;
}
#[cfg(target_arch = "wasm32")]
async fn pause_before_retry() {}

/// Acquire the revocation-state lock, with bounded retry and stale-lock
/// takeover.
///
/// Returns a [`LockGuard`] in every non-error case, including on a host that
/// doesn't support [`HostPlatform::try_create_lock_file`] — that guard just
/// has `held: false` and releasing it is a no-op, so callers never need to
/// branch on host support themselves.
async fn acquire_lock(host: &dyn HostPlatform) -> Result<LockGuard<'_>, VaultError> {
    let lock_path = host.config_dir().join(REVOCATION_LOCK_FILE);

    for attempt in 0..LOCK_MAX_ATTEMPTS {
        let marker = time::now_millis().to_string();
        match host
            .try_create_lock_file(&lock_path, marker.as_bytes())
            .await
        {
            Ok(()) => {
                return Ok(LockGuard {
                    host,
                    lock_path,
                    held: true,
                    released: false,
                });
            }
            // The trait's fail-closed default for a host that doesn't
            // implement locking — proceed under the pre-existing
            // sequential-ordering-only guarantee (see
            // `mutate_revocation_state`'s doc comment). Matched by variant,
            // not by string content: `VaultError::LockingNotSupported` is a
            // dedicated sentinel a real host's genuine failure can never
            // produce, unlike `VaultError::Other` which many unrelated
            // failure paths also use.
            Err(VaultError::LockingNotSupported { .. }) => {
                return Ok(LockGuard {
                    host,
                    lock_path,
                    held: false,
                    released: true,
                });
            }
            // Contention: someone else currently holds this lock.
            Err(VaultError::Filesystem {
                ref permission,
                ref code,
                ..
            }) if permission == "lock" && code.as_deref() == Some("EEXIST") => {
                take_over_if_stale(host, &lock_path).await;
                if attempt + 1 == LOCK_MAX_ATTEMPTS {
                    return Err(VaultError::Filesystem {
                        message: format!(
                            "Timed out waiting for the revocation-state lock at {} after {} \
                             attempts",
                            lock_path.display(),
                            LOCK_MAX_ATTEMPTS
                        ),
                        path: lock_path.display().to_string(),
                        permission: "lock".to_string(),
                        code: Some("EEXIST".to_string()),
                    });
                }
                pause_before_retry().await;
            }
            // A genuine failure (not contention, not "unsupported") — e.g.
            // permission denied, disk full. Propagate rather than retry.
            Err(other) => return Err(other),
        }
    }

    unreachable!("the loop above always returns before attempt reaches LOCK_MAX_ATTEMPTS")
}

/// Run `critical_section` (a lazily-constructed future — nothing inside it
/// runs until this function polls it, which only happens after the lock is
/// held) with the revocation-state lock held, guaranteeing the lock is
/// released before this function returns regardless of whether
/// `critical_section` succeeds or fails.
async fn with_revocation_lock<T, F>(
    host: &dyn HostPlatform,
    critical_section: F,
) -> Result<T, VaultError>
where
    F: std::future::Future<Output = Result<T, VaultError>>,
{
    let guard = acquire_lock(host).await?;
    let result = critical_section.await;
    guard.release().await;
    result
}

/// Read-modify-write a mutation into the persisted revocation state, without
/// disturbing whatever key material (`current`/`previous`/grace period) is on
/// disk at write time — the counterpart a `rotateKey`/`revokeKey` write must
/// not clobber, and vice versa (issue #298 AC10). Reuses the same atomic
/// write-temp-then-rename path [`save_key_state`] uses.
///
/// **Concurrency scope** (issue #322): wrapped in the advisory lock
/// [`with_revocation_lock`] acquires — on a host that implements
/// [`HostPlatform::try_create_lock_file`] (native — see `NativeHostPlatform`
/// in `crates/vaultkeeper-cli`), two writers whose read-modify-write windows
/// genuinely overlap (not just sequenced back-to-back) no longer race
/// last-writer-wins: the second acquirer waits (bounded retry, with
/// stale-lock takeover for an abandoned holder) until the first releases.
/// See `crates/vaultkeeper-cli/src/host.rs`'s
/// `ac10_genuinely_concurrent_revoke_and_rotate_lose_neither_mutation` and
/// `ac10_many_genuinely_concurrent_revokers_lose_no_mutation` for the tests
/// that prove this against real OS threads and a real filesystem — not two
/// sequential calls dressed up as concurrent.
///
/// On a host that does **not** implement `try_create_lock_file` (every host
/// as of this change other than `NativeHostPlatform`, including the current
/// WASM/JS bridge — see that trait method's doc comment for why) this
/// degrades to the weaker guarantee this function previously documented: a
/// `rotateKey`/`revokeKey` write and a revocation write that are *sequenced*
/// one after the other (in either order) each carry the other's portion
/// forward untouched (`ac10_sequential_revoke_and_rotate_clobber_neither_order`
/// in `crates/vaultkeeper-core/tests/lease_revocation_integration.rs`), but
/// two writers whose windows genuinely overlap can still race
/// last-writer-wins.
///
/// Requires that key state has already been persisted at least once (i.e.
/// [`crate::vault::VaultKeeper::init`] has run against this config dir) —
/// there is nothing meaningful to revoke against before any key material
/// exists. A genuinely corrupt store is also refused rather than silently
/// reset to empty: unlike [`save_key_state`] (whose caller only ever supplies
/// fresh key material and has nothing to lose from a reset), a reset here
/// would silently discard real revocations rather than merely refuse to
/// validate against them.
pub async fn mutate_revocation_state(
    host: &dyn HostPlatform,
    mutate: impl FnOnce(&mut RevocationState),
) -> Result<RevocationState, VaultError> {
    with_revocation_lock(host, mutate_revocation_state_locked(host, mutate)).await
}

async fn mutate_revocation_state_locked(
    host: &dyn HostPlatform,
    mutate: impl FnOnce(&mut RevocationState),
) -> Result<RevocationState, VaultError> {
    let parsed = match try_load_raw(host).await? {
        RawLoad::Present(parsed) => parsed,
        RawLoad::Absent => {
            return Err(VaultError::Other(
                "Cannot revoke: no key state has been persisted yet. Initialize the vault \
                 first (e.g. run `vaultkeeper doctor`)."
                    .to_string(),
            ));
        }
        RawLoad::Corrupt => {
            let state_path = host.config_dir().join(KEY_STATE_FILE);
            return Err(VaultError::Decryption {
                message: "Cannot revoke: keys.enc failed to authenticate or parse. Restore \
                          keys.enc and .keys.wrap from backup before retrying — this write \
                          must not silently discard whatever revocation state it might \
                          contain."
                    .to_string(),
                path: state_path.display().to_string(),
            });
        }
    };

    let mut revocation = revocation_from_raw(&parsed);
    mutate(&mut revocation);

    write_raw_state(
        host,
        parsed.current,
        parsed.previous,
        parsed.grace_period_expires_at,
        &revocation,
    )
    .await?;

    Ok(revocation)
}

/// Persist `snapshot` to the host's config directory. The state file and its
/// wrapping key are both written owner-only (`0o600`).
///
/// Uses write-to-temp-then-rename (via [`HostPlatform::rename_file`]) so a
/// concurrent [`load_key_state`] never observes a half-written envelope.
/// Every filesystem step (wrap-key read/write, temp write, rename) surfaces
/// the host's typed `VaultError::Filesystem` on failure rather than a generic
/// error, matching the `HostFilesystemError` contract at the wasm boundary.
///
/// Read-modify-write for the revocation portion of the file (issue #298
/// AC9): this function's caller only ever supplies key material, so before
/// writing it re-reads whatever revocation state is currently persisted and
/// carries it through untouched. `rotateKey`/`revokeKey` must never reset
/// revocation state to empty, or key rotation becomes a revocation bypass.
///
/// A currently-corrupt store refuses the write entirely, with the same
/// typed fail-closed error [`mutate_revocation_state`] uses for exactly this
/// case, rather than degrading to an empty revocation portion: writing a
/// fresh, validly-sealed envelope over an unauthenticated one would silently
/// discard whatever revocations it might contain, so a single flipped bit in
/// `keys.enc` followed by a routine rotate/revoke would silently un-revoke
/// every outstanding lease. Only a genuinely *absent* store — nothing has
/// ever been persisted, so there is nothing to lose — defaults to an empty
/// revocation portion.
///
/// **Concurrency scope** (issue #322): shares [`with_revocation_lock`] with
/// [`mutate_revocation_state`] — see that function's doc comment for exactly
/// what guarantee this does and doesn't provide depending on host locking
/// support. Sharing the same lock (rather than each function having its own)
/// is what actually closes the race this issue names: a `rotateKey` call
/// through this function and a `session revoke` call through
/// `mutate_revocation_state` mutually exclude each other, not just
/// same-function callers.
pub async fn save_key_state(
    host: &dyn HostPlatform,
    snapshot: &KeyStateSnapshot,
) -> Result<(), VaultError> {
    with_revocation_lock(host, save_key_state_locked(host, snapshot)).await
}

async fn save_key_state_locked(
    host: &dyn HostPlatform,
    snapshot: &KeyStateSnapshot,
) -> Result<(), VaultError> {
    let revocation = match try_load_raw(host).await? {
        RawLoad::Present(parsed) => revocation_from_raw(&parsed),
        RawLoad::Absent => RevocationState::default(),
        RawLoad::Corrupt => {
            let state_path = host.config_dir().join(KEY_STATE_FILE);
            return Err(VaultError::Decryption {
                message: "Cannot persist key state: keys.enc failed to authenticate or \
                          parse. Writing forward would silently discard whatever \
                          revocation state it might contain and un-revoke every \
                          outstanding lease. Restore keys.enc and .keys.wrap from backup \
                          before retrying."
                    .to_string(),
                path: state_path.display().to_string(),
            });
        }
    };

    write_raw_state(
        host,
        serialize_key(&snapshot.current),
        snapshot.previous.as_ref().map(serialize_key),
        match (&snapshot.previous, snapshot.grace_period_expires_at_ms) {
            (Some(_), Some(expiry)) => Some(expiry),
            _ => None,
        },
        &revocation,
    )
    .await
}

/// Shared envelope-encrypt-and-atomically-write path for both
/// [`save_key_state`] and [`mutate_revocation_state`].
async fn write_raw_state(
    host: &dyn HostPlatform,
    current: RawKeyMaterial,
    previous: Option<RawKeyMaterial>,
    grace_period_expires_at: Option<u64>,
    revocation: &RevocationState,
) -> Result<(), VaultError> {
    let wrap_path = host.config_dir().join(KEY_WRAP_FILE);
    let mut wrap_key = get_or_create_wrap_key(host, &wrap_path).await?;

    let raw = RawKeyState {
        version: 1,
        current,
        previous,
        grace_period_expires_at,
        rev_state_gen: revocation.rev_state_gen,
        jti: revocation.jti.iter().map(Into::into).collect(),
        key_generations: revocation.key_generations.clone(),
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
    use std::sync::{Arc, Mutex};

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
        /// Real locking support (issue #322), simulating `O_EXCL` via a
        /// single `Mutex` critical section spanning the existence check and
        /// the insert — genuine mutual exclusion, including across real OS
        /// threads racing this same in-memory host (see the concurrency
        /// tests below), not just single-threaded-test convenience.
        async fn try_create_lock_file(
            &self,
            path: &Path,
            content: &[u8],
        ) -> Result<(), VaultError> {
            let mut files = self.files.lock().unwrap();
            if files.contains_key(path) {
                return Err(VaultError::Filesystem {
                    message: format!("Lock contention: {} is already held", path.display()),
                    path: path.display().to_string(),
                    permission: "lock".to_string(),
                    code: Some("EEXIST".to_string()),
                });
            }
            files.insert(path.to_path_buf(), content.to_vec());
            Ok(())
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

    /// Flip a byte in the persisted `keys.enc` ciphertext so AES-GCM
    /// authentication fails on the next load — shared by every test that
    /// needs a store which authenticates as [`RawLoad::Corrupt`].
    async fn tamper_stored_envelope(host: &TestHost) {
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

        tamper_stored_envelope(&host).await;

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
    async fn missing_wrap_file_degrades_to_no_state_but_refuses_to_write_forward() {
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
        // A fresh wrap key was generated in its place (not left missing).
        assert!(host.file_exists(&wrap_path).await.unwrap());

        // The now-undecryptable `keys.enc` is `RawLoad::Corrupt` under the
        // fresh wrap key, so a save must refuse rather than silently
        // overwrite it — the same fail-closed contract as a byte-flipped
        // envelope, since this function cannot distinguish "wrap key lost"
        // from "ciphertext tampered" at the `RawLoad` level, and both mean
        // "whatever revocation state might be in there is about to be
        // silently discarded".
        let fresh = make_key("k-new-bbbb", 0x22, 1_705_314_600);
        let err = save_key_state(
            &host,
            &KeyStateSnapshot {
                current: fresh.clone(),
                previous: None,
                grace_period_expires_at_ms: None,
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(err, VaultError::Decryption { .. }));

        // Recovery requires explicit operator action: once the unrecoverable
        // `keys.enc` is removed (matching the documented recovery guidance),
        // the store is genuinely absent and a save proceeds normally.
        let state_path = host.config_dir().join(KEY_STATE_FILE);
        host.delete_file(&state_path).await.unwrap();
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
    async fn wrong_length_wrap_key_is_regenerated_but_save_still_refuses_on_corrupt_store() {
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
        // A fresh, correctly-sized wrap key replaced the wrong-length one...
        assert_eq!(
            host.read_file(&wrap_path).await.unwrap().len(),
            GCM_KEY_BYTES
        );

        // ...but `keys.enc` (sealed under the discarded wrong-length key) is
        // still `RawLoad::Corrupt` under the new one, so save must refuse
        // rather than panic or silently overwrite it.
        let fresh = make_key("k-new-bbbb", 0x22, 1_705_314_600);
        let err = save_key_state(
            &host,
            &KeyStateSnapshot {
                current: fresh,
                previous: None,
                grace_period_expires_at_ms: None,
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(err, VaultError::Decryption { .. }));
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

    // -------------------------------------------------------------------
    // Issue #298 — lease revocation store.
    // -------------------------------------------------------------------

    async fn seed_key_state(host: &TestHost) {
        save_key_state(
            host,
            &KeyStateSnapshot {
                current: make_key("k-1-aaaa", 0x11, 1_705_314_600),
                previous: None,
                grace_period_expires_at_ms: None,
            },
        )
        .await
        .unwrap();
    }

    /// AC4: jti entries past their own `exp` are swept on write, while
    /// `key_generations` survives the sweep untouched.
    #[tokio::test]
    async fn ac4_sweep_drops_expired_jti_but_keeps_key_generations() {
        let host = TestHost::new();
        seed_key_state(&host).await;

        mutate_revocation_state(&host, |state| {
            state.revoke_jti("expired-jti", 1_000); // already in the past
            state.revoke_jti("live-jti", 9_999_999_999);
            state.revoke_key("release-signer");
        })
        .await
        .unwrap();

        mutate_revocation_state(&host, |state| {
            let removed = state.sweep_expired(2_000);
            assert_eq!(removed, 1, "only the expired entry should be swept");
        })
        .await
        .unwrap();

        let state = load_revocation_for_validation(&host, 0).await.unwrap();
        assert!(!state.is_jti_revoked("expired-jti"));
        assert!(state.is_jti_revoked("live-jti"));
        assert_eq!(state.min_generation_for("release-signer"), 1);
    }

    /// AC6 (modification): a byte-edited `keys.enc` (broken GCM tag) fails
    /// closed with a typed `TokenRevoked` error, not silently treated as "no
    /// revocations".
    #[tokio::test]
    async fn ac6_tampered_envelope_fails_closed_for_lease_validation() {
        let host = TestHost::new();
        seed_key_state(&host).await;
        mutate_revocation_state(&host, |state| {
            state.revoke_jti("some-jti", 9_999_999_999);
        })
        .await
        .unwrap();

        tamper_stored_envelope(&host).await;

        let err = load_revocation_for_validation(&host, 0).await.unwrap_err();
        match err {
            VaultError::TokenRevoked { message } => {
                assert!(
                    message.contains("authenticate") || message.contains("parse"),
                    "expected a modification-specific message, got: {message}"
                );
            }
            other => panic!("expected VaultError::TokenRevoked, got {other:?}"),
        }
    }

    /// AC7 (rollback): restoring an earlier, validly-sealed copy of the store
    /// (lower `revStateGen`) fails closed rather than silently un-revoking.
    #[tokio::test]
    async fn ac7_rollback_to_earlier_valid_envelope_fails_closed() {
        let host = TestHost::new();
        seed_key_state(&host).await;

        mutate_revocation_state(&host, |state| {
            state.revoke_jti("first-revocation", 9_999_999_999);
        })
        .await
        .unwrap();
        let state_path = host.config_dir().join(KEY_STATE_FILE);
        let earlier_envelope = host.read_file(&state_path).await.unwrap();
        let earlier_gen = load_revocation_for_validation(&host, 0)
            .await
            .unwrap()
            .rev_state_gen;

        mutate_revocation_state(&host, |state| {
            state.revoke_jti("second-revocation", 9_999_999_999);
        })
        .await
        .unwrap();
        let later_gen = load_revocation_for_validation(&host, earlier_gen)
            .await
            .unwrap()
            .rev_state_gen;
        assert!(later_gen > earlier_gen);

        // Attacker (or a stale backup restore) rolls the file back to the
        // earlier, validly-sealed envelope.
        host.write_file(&state_path, &earlier_envelope, 0o600)
            .await
            .unwrap();

        let err = load_revocation_for_validation(&host, later_gen)
            .await
            .unwrap_err();
        match err {
            VaultError::TokenRevoked { message } => {
                assert!(
                    message.contains("rollback"),
                    "expected a rollback-specific message, got: {message}"
                );
            }
            other => panic!("expected VaultError::TokenRevoked, got {other:?}"),
        }
    }

    /// AC8 (deletion): a missing `keys.enc` fails closed for lease
    /// validation with a message naming the absence, distinct from a
    /// tampered/rolled-back store.
    #[tokio::test]
    async fn ac8_missing_store_fails_closed_with_a_distinct_message() {
        let host = TestHost::new();
        // No `seed_key_state` call — the store was never persisted.
        let err = load_revocation_for_validation(&host, 0).await.unwrap_err();
        match err {
            VaultError::TokenRevoked { message } => {
                assert!(
                    message.contains("missing"),
                    "expected a missing-store-specific message, got: {message}"
                );
            }
            other => panic!("expected VaultError::TokenRevoked, got {other:?}"),
        }
    }

    /// Companion to [`ac6_tampered_envelope_fails_closed_for_lease_validation`]:
    /// a truncated/malformed (not merely byte-flipped) `keys.enc` must fail
    /// closed the same way — the same [`RawLoad::Corrupt`] path covers both
    /// "authentication failed" and "didn't even parse as an envelope".
    #[tokio::test]
    async fn truncated_store_fails_closed_for_lease_validation() {
        let host = TestHost::new();
        seed_key_state(&host).await;
        mutate_revocation_state(&host, |state| {
            state.revoke_jti("some-jti", 9_999_999_999);
        })
        .await
        .unwrap();

        // Truncate mid-envelope: keep only the IV segment, dropping the
        // authTag and ciphertext entirely.
        let state_path = host.config_dir().join(KEY_STATE_FILE);
        let envelope = String::from_utf8(host.read_file(&state_path).await.unwrap()).unwrap();
        let iv_only = envelope.split(':').next().unwrap().to_string();
        host.write_file(&state_path, iv_only.as_bytes(), 0o600)
            .await
            .unwrap();

        let err = load_revocation_for_validation(&host, 0).await.unwrap_err();
        match err {
            VaultError::TokenRevoked { message } => {
                assert!(
                    message.contains("authenticate") || message.contains("parse"),
                    "expected a modification/corruption-specific message, got: {message}"
                );
            }
            other => panic!("expected VaultError::TokenRevoked, got {other:?}"),
        }
    }

    /// AC9/AC10 groundwork: `save_key_state` (the path `rotateKey`/
    /// `revokeKey` use) must never reset revocation state to empty, and
    /// `mutate_revocation_state` must never disturb key material.
    #[tokio::test]
    async fn revocation_state_survives_a_key_material_only_save() {
        let host = TestHost::new();
        seed_key_state(&host).await;
        mutate_revocation_state(&host, |state| {
            state.revoke_jti("survives-rotation", 9_999_999_999);
            state.revoke_key("release-signer");
        })
        .await
        .unwrap();

        // Simulates `rotateKey`'s `persist_key_state`: a fresh snapshot built
        // purely from key material, with no knowledge of revocation state.
        save_key_state(
            &host,
            &KeyStateSnapshot {
                current: make_key("k-2-bbbb", 0x22, 1_705_314_600),
                previous: Some(make_key("k-1-aaaa", 0x11, 1_705_300_000)),
                grace_period_expires_at_ms: Some((time::now_millis() + 60_000) as u64),
            },
        )
        .await
        .unwrap();

        let state = load_revocation_for_validation(&host, 0).await.unwrap();
        assert!(state.is_jti_revoked("survives-rotation"));
        assert_eq!(state.min_generation_for("release-signer"), 1);

        // And the reverse: a revocation mutation must not disturb the
        // rotated key material.
        mutate_revocation_state(&host, |state| {
            state.revoke_jti("another-jti", 9_999_999_999);
        })
        .await
        .unwrap();
        let loaded = load_key_state(&host).await.unwrap().unwrap();
        assert_eq!(loaded.current.id, "k-2-bbbb");
        assert_eq!(
            loaded.previous.as_ref().map(|k| k.id.as_str()),
            Some("k-1-aaaa")
        );
    }

    #[tokio::test]
    async fn mutate_revocation_state_refuses_when_no_key_state_persisted_yet() {
        let host = TestHost::new();
        let err = mutate_revocation_state(&host, |state| {
            state.revoke_jti("jti", 9_999_999_999);
        })
        .await
        .unwrap_err();
        assert!(matches!(err, VaultError::Other(_)));
    }

    // -------------------------------------------------------------------
    // Regression: `save_key_state` must refuse to write over a corrupt
    // store rather than silently defaulting the revocation portion to
    // empty (a single flipped bit in `keys.enc` followed by a routine
    // rotate/revoke would otherwise silently un-revoke every outstanding
    // lease).
    // -------------------------------------------------------------------

    /// Simulates `rotate_key`'s `persist_key_state` call against a corrupt
    /// store: it must refuse with a typed error, and must not touch the
    /// on-disk file at all.
    #[tokio::test]
    async fn save_key_state_refuses_on_corrupt_store_simulating_rotate() {
        let host = TestHost::new();
        seed_key_state(&host).await;
        mutate_revocation_state(&host, |state| {
            state.revoke_jti("pre-corruption-jti", 9_999_999_999);
        })
        .await
        .unwrap();

        tamper_stored_envelope(&host).await;
        let state_path = host.config_dir().join(KEY_STATE_FILE);
        let before = host.read_file(&state_path).await.unwrap();

        // A rotation would supply fresh current/previous key material, with
        // no knowledge of (and no intent to touch) revocation state.
        let err = save_key_state(
            &host,
            &KeyStateSnapshot {
                current: make_key("k-2-bbbb", 0x22, 1_705_314_600),
                previous: Some(make_key("k-1-aaaa", 0x11, 1_705_300_000)),
                grace_period_expires_at_ms: Some((time::now_millis() + 60_000) as u64),
            },
        )
        .await
        .unwrap_err();

        assert!(
            matches!(err, VaultError::Decryption { .. }),
            "expected VaultError::Decryption, got {err:?}"
        );
        let after = host.read_file(&state_path).await.unwrap();
        assert_eq!(before, after, "corrupt store must be left byte-identical");
    }

    /// Same as above but simulating `revoke_key`'s `persist_key_state` call
    /// (only `current` supplied, no `previous`/grace period).
    #[tokio::test]
    async fn save_key_state_refuses_on_corrupt_store_simulating_revoke() {
        let host = TestHost::new();
        seed_key_state(&host).await;
        mutate_revocation_state(&host, |state| {
            state.revoke_jti("pre-corruption-jti-2", 9_999_999_999);
        })
        .await
        .unwrap();

        tamper_stored_envelope(&host).await;
        let state_path = host.config_dir().join(KEY_STATE_FILE);
        let before = host.read_file(&state_path).await.unwrap();

        let err = save_key_state(
            &host,
            &KeyStateSnapshot {
                current: make_key("k-revoked-cccc", 0x33, 1_705_314_600),
                previous: None,
                grace_period_expires_at_ms: None,
            },
        )
        .await
        .unwrap_err();

        assert!(
            matches!(err, VaultError::Decryption { .. }),
            "expected VaultError::Decryption, got {err:?}"
        );
        let after = host.read_file(&state_path).await.unwrap();
        assert_eq!(before, after, "corrupt store must be left byte-identical");
    }

    // -------------------------------------------------------------------
    // Regression: a read failure on a `keys.enc` that exists (permission
    // denied, transient I/O error) must not be classified the same as
    // "the file was never created" — `try_load_raw` now propagates it as a
    // typed error instead of collapsing to `RawLoad::Absent`.
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn unreadable_existing_state_file_surfaces_as_typed_error_not_absent() {
        let host = TestHost::new();
        seed_key_state(&host).await;

        let state_path = host.config_dir().join(KEY_STATE_FILE);
        host.deny_read.lock().unwrap().insert(state_path.clone());

        let err = load_key_state(&host).await.unwrap_err();
        match err {
            VaultError::Filesystem {
                path, permission, ..
            } => {
                assert_eq!(path, state_path.display().to_string());
                assert_eq!(permission, "read");
            }
            other => panic!("expected VaultError::Filesystem, got {other:?}"),
        }
    }

    /// Same classification bug, exercised through the lease-revocation
    /// loader: an unreadable-but-present store must not resolve to "no
    /// revocations" (which `RawLoad::Absent` would trigger via a distinct,
    /// misleading "keys.enc is missing" message).
    #[tokio::test]
    async fn unreadable_existing_state_file_surfaces_as_typed_error_for_lease_validation() {
        let host = TestHost::new();
        seed_key_state(&host).await;

        let state_path = host.config_dir().join(KEY_STATE_FILE);
        host.deny_read.lock().unwrap().insert(state_path.clone());

        let err = load_revocation_for_validation(&host, 0).await.unwrap_err();
        assert!(
            matches!(err, VaultError::Filesystem { .. }),
            "expected VaultError::Filesystem (not a TokenRevoked \"missing\" collapse), got {err:?}"
        );
    }

    // -------------------------------------------------------------------
    // Issue #322 — cross-process revocation-state lock.
    // -------------------------------------------------------------------

    /// A host that implements no `HostPlatform` capability beyond the bare
    /// minimum required by the trait — every optional method (including
    /// `try_create_lock_file`) is left at its default. Stands in for the
    /// WASM/JS bridge's documented fallback (`JsHostPlatform` does not
    /// override `try_create_lock_file` either — see that struct's doc
    /// comment in `crates/vaultkeeper-wasm/src/wasm_impl.rs`), without
    /// pulling in a wasm32 target to exercise it.
    struct DefaultLockHost {
        config_dir: PathBuf,
    }

    #[async_trait::async_trait]
    impl HostPlatform for DefaultLockHost {
        async fn exec(
            &self,
            _cmd: &str,
            _args: &[&str],
            _options: ExecOptions<'_>,
        ) -> Result<ExecOutput, VaultError> {
            unimplemented!("not exercised by this test")
        }
        async fn read_file(&self, _path: &Path) -> Result<Vec<u8>, VaultError> {
            unimplemented!("not exercised by this test")
        }
        async fn write_file(
            &self,
            _path: &Path,
            _content: &[u8],
            _mode: u32,
        ) -> Result<(), VaultError> {
            unimplemented!("not exercised by this test")
        }
        async fn file_exists(&self, _path: &Path) -> Result<bool, VaultError> {
            unimplemented!("not exercised by this test")
        }
        async fn delete_file(&self, _path: &Path) -> Result<(), VaultError> {
            unimplemented!("not exercised by this test")
        }
        async fn list_dir(&self, _path: &Path) -> Result<Vec<String>, VaultError> {
            unimplemented!("not exercised by this test")
        }
        fn platform(&self) -> Platform {
            Platform::Linux
        }
        fn config_dir(&self) -> &Path {
            &self.config_dir
        }
    }

    /// The wasm/JS bridge contract (issue #322): a host that doesn't
    /// override `try_create_lock_file` — every `HostPlatform` implementation
    /// as of this change other than `NativeHostPlatform`, including
    /// `JsHostPlatform` — gets the trait's fail-closed default: a typed
    /// error, never a silent `Ok(())`. A silently-permissive default would
    /// let two overlapping writers both believe they hold an exclusive lock,
    /// which is the exact bug this issue exists to fix, one layer up.
    #[tokio::test]
    async fn default_try_create_lock_file_fails_closed_not_permissively() {
        let host = DefaultLockHost {
            config_dir: PathBuf::from("/test/config"),
        };
        let err = host
            .try_create_lock_file(Path::new("/test/config/keys.enc.lock"), b"123")
            .await
            .unwrap_err();
        assert!(
            matches!(err, VaultError::LockingNotSupported { .. }),
            "expected the fail-closed default (VaultError::LockingNotSupported), got {err:?}"
        );
    }

    /// Regression test for issue #322 review feedback: `acquire_lock` must
    /// only treat the dedicated `VaultError::LockingNotSupported` sentinel as
    /// "this host doesn't support locking" — a genuine `VaultError::Other`
    /// failure from a real host's `try_create_lock_file` (e.g. some
    /// unrelated I/O error the host chose to report generically) must
    /// propagate as a hard error instead of being silently downgraded to
    /// "proceed unlocked". Before the fix, `acquire_lock` matched on
    /// `Err(VaultError::Other(_))`, which could not distinguish "locking
    /// unsupported" from any other `Other`-shaped failure.
    #[tokio::test]
    async fn acquire_lock_propagates_a_genuine_other_error_instead_of_downgrading_it() {
        struct OtherErrorHost {
            config_dir: PathBuf,
        }

        #[async_trait::async_trait]
        impl HostPlatform for OtherErrorHost {
            async fn exec(
                &self,
                _cmd: &str,
                _args: &[&str],
                _options: ExecOptions<'_>,
            ) -> Result<ExecOutput, VaultError> {
                unimplemented!("not exercised by this test")
            }
            async fn read_file(&self, _path: &Path) -> Result<Vec<u8>, VaultError> {
                unimplemented!("not exercised by this test")
            }
            async fn write_file(
                &self,
                _path: &Path,
                _content: &[u8],
                _mode: u32,
            ) -> Result<(), VaultError> {
                unimplemented!("not exercised by this test")
            }
            async fn file_exists(&self, _path: &Path) -> Result<bool, VaultError> {
                unimplemented!("not exercised by this test")
            }
            async fn delete_file(&self, _path: &Path) -> Result<(), VaultError> {
                unimplemented!("not exercised by this test")
            }
            async fn list_dir(&self, _path: &Path) -> Result<Vec<String>, VaultError> {
                unimplemented!("not exercised by this test")
            }
            async fn try_create_lock_file(
                &self,
                _path: &Path,
                _content: &[u8],
            ) -> Result<(), VaultError> {
                Err(VaultError::Other(
                    "some unrelated failure this host chose to report generically".into(),
                ))
            }
            fn platform(&self) -> Platform {
                Platform::Linux
            }
            fn config_dir(&self) -> &Path {
                &self.config_dir
            }
        }

        let host = OtherErrorHost {
            config_dir: PathBuf::from("/test/config"),
        };
        // `LockGuard` (the `Ok` type) intentionally doesn't implement
        // `Debug` (see its struct doc comment — it deliberately isn't
        // meant to be inspected/printed), so `unwrap_err()` isn't available
        // here; match instead.
        let result = acquire_lock(&host).await;
        let err = match result {
            Err(err) => err,
            Ok(_) => panic!("expected acquire_lock to propagate the genuine Other failure"),
        };
        assert!(
            matches!(err, VaultError::Other(_)),
            "a genuine Other failure must propagate, not be downgraded to unlocked; got {err:?}"
        );
    }

    /// Host double whose lock is permanently contended
    /// (`try_create_lock_file` unconditionally reports `EEXIST`) and whose
    /// lock marker always reads back as freshly created (`now_millis()` on
    /// every read) so `take_over_if_stale` never considers it abandoned.
    /// Used by
    /// [`acquire_lock_times_out_after_lock_max_attempts_when_contention_never_clears`]
    /// to exercise the `attempt + 1 == LOCK_MAX_ATTEMPTS` branch — every
    /// other contention test in this module resolves via a successful
    /// retry or a stale-lock takeover, so that timeout arm otherwise has no
    /// coverage.
    struct AlwaysContendedFreshHost {
        config_dir: PathBuf,
    }

    #[async_trait::async_trait]
    impl HostPlatform for AlwaysContendedFreshHost {
        async fn exec(
            &self,
            _cmd: &str,
            _args: &[&str],
            _options: ExecOptions<'_>,
        ) -> Result<ExecOutput, VaultError> {
            unimplemented!("not exercised by this test")
        }
        async fn read_file(&self, _path: &Path) -> Result<Vec<u8>, VaultError> {
            // Always "just created" — never stale, so `take_over_if_stale`
            // never fires and the retry loop must run to genuine
            // exhaustion rather than resolving via takeover.
            Ok(time::now_millis().to_string().into_bytes())
        }
        async fn write_file(
            &self,
            _path: &Path,
            _content: &[u8],
            _mode: u32,
        ) -> Result<(), VaultError> {
            unimplemented!("not exercised by this test")
        }
        async fn file_exists(&self, _path: &Path) -> Result<bool, VaultError> {
            unimplemented!("not exercised by this test")
        }
        async fn delete_file(&self, _path: &Path) -> Result<(), VaultError> {
            // `take_over_if_stale` would call this if it ever decided the
            // marker was stale, which it never does here — present only so
            // the trait is satisfied.
            Ok(())
        }
        async fn list_dir(&self, _path: &Path) -> Result<Vec<String>, VaultError> {
            unimplemented!("not exercised by this test")
        }
        async fn try_create_lock_file(
            &self,
            path: &Path,
            _content: &[u8],
        ) -> Result<(), VaultError> {
            Err(VaultError::Filesystem {
                message: format!("Lock contention: {} is already held", path.display()),
                path: path.display().to_string(),
                permission: "lock".to_string(),
                code: Some("EEXIST".to_string()),
            })
        }
        fn platform(&self) -> Platform {
            Platform::Linux
        }
        fn config_dir(&self) -> &Path {
            &self.config_dir
        }
    }

    /// Regression test for a coverage gap in `acquire_lock`'s bounded-retry
    /// loop: the `attempt + 1 == LOCK_MAX_ATTEMPTS` timeout branch (never
    /// resolving via a successful retry or a stale-lock takeover) had zero
    /// test coverage. Uses [`AlwaysContendedFreshHost`], whose lock is both
    /// permanently contended and permanently "fresh", to force every one of
    /// `LOCK_MAX_ATTEMPTS` attempts to hit contention and run out.
    ///
    /// Fast by construction: `pause_before_retry`'s per-attempt delay is
    /// `RETRY_PAUSE_MS` (2ms, see that constant), so `LOCK_MAX_ATTEMPTS`
    /// (50) attempts cost roughly 100ms total — comfortably sub-second,
    /// without touching either production constant or adding a sleep here.
    #[tokio::test]
    async fn acquire_lock_times_out_after_lock_max_attempts_when_contention_never_clears() {
        let host = AlwaysContendedFreshHost {
            config_dir: PathBuf::from("/test/config"),
        };

        let result = acquire_lock(&host).await;
        let err = match result {
            Err(err) => err,
            Ok(_) => panic!("expected acquire_lock to time out, not succeed"),
        };
        assert!(
            matches!(
                err,
                VaultError::Filesystem {
                    ref permission,
                    ref code,
                    ..
                } if permission == "lock" && code.as_deref() == Some("EEXIST")
            ),
            "expected the timeout arm's Filesystem/lock/EEXIST shape, got {err:?}"
        );
        if let VaultError::Filesystem { ref message, .. } = err {
            assert!(
                message.contains("Timed out waiting"),
                "expected the timeout message, got {message:?}"
            );
        }
    }

    /// `acquire_lock` treats that same fail-closed default as "this host
    /// doesn't support locking" and proceeds without one, rather than
    /// propagating it as a hard failure — a `mutate_revocation_state` call
    /// against a non-locking host must still succeed exactly as it did
    /// before issue #322 (the pre-existing sequential-ordering-only
    /// guarantee), not start refusing every call outright.
    #[tokio::test]
    async fn non_locking_host_still_completes_revocation_writes() {
        let host = TestHost::new();
        seed_key_state(&host).await;

        // TestHost overrides `try_create_lock_file` with real locking
        // support (used by the concurrency tests below) — this test instead
        // exercises the *unsupported* path directly through the shared
        // `acquire_lock`/`with_revocation_lock` machinery via
        // `DefaultLockHost`, then confirms `mutate_revocation_state` itself
        // (against the ordinary, locking-capable `TestHost`) is unaffected
        // either way: both hosts complete the write.
        let default_host = DefaultLockHost {
            config_dir: PathBuf::from("/test/config"),
        };
        let guard = acquire_lock(&default_host).await.unwrap();
        guard.release().await;

        let result = mutate_revocation_state(&host, |state| {
            state.revoke_jti("still-works-jti", 9_999_999_999);
        })
        .await
        .unwrap();
        assert!(result.is_jti_revoked("still-works-jti"));
    }

    /// Issue #322 AC: the lock is released promptly on the error/early-return
    /// path, not just on success — a corrupt store makes
    /// `mutate_revocation_state` fail closed (see
    /// `ac6_tampered_envelope_fails_closed_for_lease_validation`), and that
    /// failure must not leave the lock file behind for the next caller to
    /// wait out a full stale-lock timeout on.
    #[tokio::test]
    async fn lock_is_released_immediately_when_the_critical_section_errors() {
        let host = TestHost::new();
        seed_key_state(&host).await;
        tamper_stored_envelope(&host).await;

        let lock_path = host.config_dir().join(REVOCATION_LOCK_FILE);

        let err = mutate_revocation_state(&host, |state| {
            state.revoke_jti("never-applied-jti", 9_999_999_999);
        })
        .await
        .unwrap_err();
        assert!(matches!(err, VaultError::Decryption { .. }));

        assert!(
            !host.file_exists(&lock_path).await.unwrap(),
            "the lock file must not survive a failed critical section"
        );

        // Proves the release was real, not merely "the file happens to be
        // absent": a fresh acquisition succeeds immediately (no contention),
        // which would fail/hang were the lock still held.
        let guard = acquire_lock(&host).await.unwrap();
        guard.release().await;
    }

    /// Issue #322 AC: stale-lock takeover. A lock file left behind with an
    /// acquisition timestamp far enough in the past to be considered
    /// abandoned (standing in for a holder that crashed or panicked before
    /// reaching `LockGuard::release`) does not permanently wedge
    /// acquisition — see `LockGuard`'s doc comment for why recovering a
    /// panic-abandoned lock is this takeover's job, not `Drop`'s.
    #[tokio::test]
    async fn stale_lock_left_by_a_panicked_holder_is_taken_over() {
        let host = TestHost::new();
        seed_key_state(&host).await;

        let lock_path = host.config_dir().join(REVOCATION_LOCK_FILE);
        // "0" epoch milliseconds — always older than `LOCK_STALE_AFTER_MS`.
        host.write_file(&lock_path, b"0", 0o600).await.unwrap();

        let result = mutate_revocation_state(&host, |state| {
            state.revoke_jti("post-takeover-jti", 9_999_999_999);
        })
        .await
        .unwrap();
        assert!(result.is_jti_revoked("post-takeover-jti"));
    }

    /// A panic inside `with_revocation_lock`'s critical section is the one
    /// path that reaches `LockGuard::drop` without `release()` having run
    /// (see that struct's doc comment). This test drives a real panic
    /// through a real (spawned) unwind — rather than asserting on `Drop`'s
    /// internals directly — and confirms two things: the lock left behind
    /// is recovered by the ordinary stale-lock takeover path (not by
    /// `Drop` itself), and `Drop`'s `debug_assert` safety net does not fire
    /// on this path. That assert only skips when
    /// `std::thread::panicking()` is true; if it fired anyway it would be a
    /// panic raised while already unwinding from another panic, which
    /// aborts the process outright — so this test completing at all (rather
    /// than the whole binary aborting) is itself proof the guard's `Drop`
    /// stayed silent here, as designed.
    ///
    /// `with_revocation_lock` is async, so a synchronous
    /// `std::panic::catch_unwind` around it doesn't cleanly apply across
    /// `.await` points; a spawned task's `JoinHandle` gives the same
    /// "did it panic" signal without fighting the executor.
    #[tokio::test]
    async fn panicking_critical_section_is_recovered_by_stale_lock_takeover() {
        let host = Arc::new(TestHost::new());
        seed_key_state(&host).await;

        let lock_path = host.config_dir().join(REVOCATION_LOCK_FILE);

        let task_host = Arc::clone(&host);
        let join_result = tokio::spawn(async move {
            with_revocation_lock::<(), _>(&*task_host, async {
                panic!("simulated panic inside the revocation-state critical section");
            })
            .await
        })
        .await;

        let join_err = join_result.expect_err("expected the spawned task to have panicked");
        assert!(
            join_err.is_panic(),
            "expected a panic-flavored JoinError, got {join_err:?}"
        );

        // The panic pre-empted `LockGuard::release`, so the lock file is
        // left behind — abandoned, not released — exactly as a real
        // crashed process would leave it.
        assert!(
            host.file_exists(&lock_path).await.unwrap(),
            "the panicked holder's lock file must still be present, not released"
        );

        // Simulate the passage of time past `LOCK_STALE_AFTER_MS`, the same
        // synthetic-stale-marker technique
        // `stale_lock_left_by_a_panicked_holder_is_taken_over` uses above.
        host.write_file(&lock_path, b"0", 0o600).await.unwrap();

        let result = mutate_revocation_state(&*host, |state| {
            state.revoke_jti("post-panic-takeover-jti", 9_999_999_999);
        })
        .await
        .unwrap();
        assert!(result.is_jti_revoked("post-panic-takeover-jti"));
    }

    /// A lock file whose content isn't a parseable timestamp (never written
    /// by this module) must never be taken over — `take_over_if_stale` only
    /// recovers locks it recognizes as its own, not an arbitrary file that
    /// happens to occupy the lock path.
    #[tokio::test]
    async fn malformed_lock_marker_is_never_treated_as_stale() {
        let host = TestHost::new();
        let lock_path = host.config_dir().join(REVOCATION_LOCK_FILE);
        host.write_file(&lock_path, b"not-a-timestamp", 0o600)
            .await
            .unwrap();

        take_over_if_stale(&host, &lock_path).await;

        assert!(
            host.file_exists(&lock_path).await.unwrap(),
            "a malformed marker must be left in place, not taken over"
        );
    }

    /// A host wrapper that simulates a *second* contender taking over the
    /// same stale lock in the gap between `take_over_if_stale`'s two reads
    /// of the marker — used by
    /// [`take_over_if_stale_never_deletes_a_lock_recreated_between_its_reads`]
    /// to deterministically reproduce the exact interleaving issue #322
    /// review flagged, rather than relying on real thread-scheduling timing
    /// (which could pass or fail depending on luck).
    struct RaceDuringTakeoverHost {
        inner: TestHost,
        /// Number of `read_file` calls observed for the lock path so far.
        lock_reads: std::sync::atomic::AtomicUsize,
    }

    #[async_trait::async_trait]
    impl HostPlatform for RaceDuringTakeoverHost {
        async fn exec(
            &self,
            cmd: &str,
            args: &[&str],
            options: ExecOptions<'_>,
        ) -> Result<ExecOutput, VaultError> {
            self.inner.exec(cmd, args, options).await
        }
        async fn read_file(&self, path: &Path) -> Result<Vec<u8>, VaultError> {
            if path == self.inner.config_dir().join(REVOCATION_LOCK_FILE) {
                let call = self
                    .lock_reads
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if call == 1 {
                    // This is `take_over_if_stale`'s confirmation read — the
                    // second time it reads the lock marker, immediately
                    // before it would otherwise delete it. Simulate a
                    // second contender winning the takeover race first: it
                    // deleted the stale marker and created its own fresh,
                    // valid lock, right in this gap.
                    self.inner
                        .write_file(path, b"fresh-holders-marker", 0o600)
                        .await
                        .unwrap();
                }
            }
            self.inner.read_file(path).await
        }
        async fn write_file(
            &self,
            path: &Path,
            content: &[u8],
            mode: u32,
        ) -> Result<(), VaultError> {
            self.inner.write_file(path, content, mode).await
        }
        async fn file_exists(&self, path: &Path) -> Result<bool, VaultError> {
            self.inner.file_exists(path).await
        }
        async fn delete_file(&self, path: &Path) -> Result<(), VaultError> {
            self.inner.delete_file(path).await
        }
        async fn rename_file(&self, from: &Path, to: &Path) -> Result<(), VaultError> {
            self.inner.rename_file(from, to).await
        }
        async fn list_dir(&self, path: &Path) -> Result<Vec<String>, VaultError> {
            self.inner.list_dir(path).await
        }
        async fn try_create_lock_file(
            &self,
            path: &Path,
            content: &[u8],
        ) -> Result<(), VaultError> {
            self.inner.try_create_lock_file(path, content).await
        }
        fn platform(&self) -> Platform {
            self.inner.platform()
        }
        fn config_dir(&self) -> &Path {
            self.inner.config_dir()
        }
    }

    /// Regression test for issue #322 review feedback: `take_over_if_stale`
    /// must not delete a lock file that a concurrent contender has already
    /// taken over and recreated in the window between this function's
    /// staleness read and its delete call. Before the fix, an unconditional
    /// delete at that point would tear down the *new* holder's valid lock
    /// (not the stale one this function decided to reap), letting a third
    /// party acquire the now-vacant path too — two simultaneous holders,
    /// exactly the bug this whole mechanism exists to prevent.
    #[tokio::test]
    async fn take_over_if_stale_never_deletes_a_lock_recreated_between_its_reads() {
        let inner = TestHost::new();
        let lock_path = inner.config_dir().join(REVOCATION_LOCK_FILE);
        // "0" epoch milliseconds — always older than `LOCK_STALE_AFTER_MS`,
        // so the first read correctly judges this stale.
        inner.write_file(&lock_path, b"0", 0o600).await.unwrap();

        let host = RaceDuringTakeoverHost {
            inner,
            lock_reads: std::sync::atomic::AtomicUsize::new(0),
        };

        take_over_if_stale(&host, &lock_path).await;

        assert_eq!(
            host.inner.read_file(&lock_path).await.unwrap(),
            b"fresh-holders-marker",
            "the concurrent contender's freshly recreated lock must survive \
             take_over_if_stale untouched"
        );
    }

    /// Regression test for issue #322 review feedback: `pause_before_retry`
    /// must not block the OS thread it is polled on — a blocking
    /// `std::thread::sleep` there would stall every other task sharing that
    /// thread (all of them, on a single-threaded runtime) for the pause's
    /// duration, not just this lock's own contention loop.
    ///
    /// Proven by timing, not by inspecting internals: two `pause_before_retry`
    /// futures run concurrently (`tokio::join!`) on a deliberately
    /// **single-threaded** runtime. A blocking implementation would
    /// serialize them — the single worker thread can't poll the second
    /// future until the first one's blocking sleep call returns — so total
    /// elapsed time would be roughly double one pause. A genuinely
    /// non-blocking implementation lets the executor poll both while
    /// neither is actually occupying the thread, so elapsed time stays close
    /// to a single pause. The threshold below (`< 3x` a single pause) is
    /// comfortably below the `~2x` a blocking implementation would produce,
    /// while generous enough to absorb ordinary CI scheduling jitter on a
    /// tiny multi-millisecond duration.
    #[tokio::test(flavor = "current_thread")]
    async fn pause_before_retry_does_not_block_the_polling_thread() {
        let start = std::time::Instant::now();
        tokio::join!(pause_before_retry(), pause_before_retry());
        let elapsed = start.elapsed();

        assert!(
            elapsed < std::time::Duration::from_millis(RETRY_PAUSE_MS * 3),
            "two concurrent pauses took {elapsed:?}, suggesting they were serialized by a \
             blocking sleep rather than run concurrently (single pause is {RETRY_PAUSE_MS}ms)"
        );
    }

    /// Issue #322 AC: two genuinely overlapping mutators — real OS threads,
    /// no barrier forcing serialization — racing `mutate_revocation_state`
    /// against the same in-memory host lose no mutation. Complements the
    /// real-filesystem version of this test in
    /// `crates/vaultkeeper-cli/src/host.rs` (`ac10_many_genuinely_concurrent_revokers_lose_no_mutation`);
    /// this one is fast and deterministic enough to also double as a tight
    /// regression guard, since `TestHost::try_create_lock_file` provides
    /// real mutual exclusion via a shared `Mutex` (see that impl's doc
    /// comment), not an approximation.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn ac10_genuinely_concurrent_revokers_against_in_memory_host_lose_no_mutation() {
        const N: usize = 32;

        let host = Arc::new(TestHost::new());
        seed_key_state(&host).await;

        let mut tasks = Vec::with_capacity(N);
        for i in 0..N {
            let task_host = Arc::clone(&host);
            tasks.push(tokio::spawn(async move {
                mutate_revocation_state(task_host.as_ref(), move |state| {
                    state.revoke_jti(format!("jti-{i}"), 9_999_999_999);
                })
                .await
                .unwrap();
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }

        let revocation = load_revocation_for_validation(host.as_ref(), 0)
            .await
            .unwrap();
        for i in 0..N {
            assert!(
                revocation.is_jti_revoked(&format!("jti-{i}")),
                "revocation of jti-{i} was lost to a concurrent writer"
            );
        }
    }
}
