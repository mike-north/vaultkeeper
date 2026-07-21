//! Opaque capability-handle table (issue #241).
//!
//! `VaultKeeper::authorize()` used to hand validated [`VaultClaims`] — the raw
//! secret (`val`) included — straight back to the caller (mirroring the WASM
//! layer's pre-#241 `WasmAuthorization { claims, response, secret }`, which
//! collapsed authorize into one call and returned the plaintext secret
//! immediately). That shape must never leak into the public TypeScript
//! package's security model, where a `CapabilityToken`
//! (`packages/vaultkeeper/src/identity/session.ts`) is deliberately opaque:
//! the claims live in a module-private `WeakMap`, and reading the secret is a
//! separate, explicit, one-time step (`getSecret`/`SecretAccessor`).
//!
//! [`HandleTable`] is the core-side equivalent: `authorize()` (and, in the
//! future, a signing-key authorize path) retains validated claims — including
//! the secret, held in a [`Zeroizing`] buffer — behind an opaque [`HandleId`].
//! Callers resolve non-secret claims for fetch/exec/sign consumers via
//! [`HandleTable::resolve_secret_claims`]/[`HandleTable::resolve_signing_claims`]
//! (no secret egress), and read the secret exactly once via
//! [`HandleTable::read_secret`] — a second read returns
//! [`VaultError::AccessorConsumed`] (issue #236).
//!
//! # Signing vs. secret discrimination (AC3)
//!
//! A handle wraps either [`StoredClaims::Secret`] or [`StoredClaims::Signing`]
//! claims, mirroring the TypeScript union's `isSigningClaims` discriminator.
//! `resolve_secret_claims`/`read_secret` refuse a signing-key handle, and
//! `resolve_signing_claims` refuses a secret handle — both with
//! [`VaultError::AuthorizationDenied`], matching
//! `AuthorizationDeniedError` on the TypeScript side exactly (`getSecret()`
//! rejecting a signing token, `sign()` rejecting a secret token).
//!
//! # Lifetime / eviction policy (AC4 — flagged open design item)
//!
//! Every handle is evicted by exactly one of three paths:
//!
//! 1. **Explicit release** ([`HandleTable::release`]) — the primary, cheap
//!    path. A caller that is done with a handle (e.g. the TS wasm bridge,
//!    once its `CapabilityToken` wrapper is finished with it) releases it
//!    immediately rather than waiting on the paths below.
//! 2. **Usage-limit exhaustion** — governed by the *token's own*
//!    `use_limit` claim, tracked by [`HandleTable::record_usage`] (see
//!    below), exactly as `VaultKeeper::authorize()` already blocked
//!    over-used JWEs before this issue.
//! 3. **Expiry sweep** — each handle carries an `expires_at: Option<u64>`
//!    (Unix seconds) supplied by the caller at insert time.
//!    [`HandleTable::resolve_secret_claims`]/`resolve_signing_claims`/
//!    `read_secret` all check it lazily (no background timer — this table
//!    is embedded in several sync/async host runtimes with no shared clock
//!    thread), and [`HandleTable::sweep_expired`] is exposed for a host that
//!    wants to sweep proactively (e.g. a CLI daemon loop). A stale handle is
//!    never resolvable past its `expires_at`, whether or not anyone calls
//!    `sweep_expired` first.
//!
//! As a defense-in-depth backstop against unbounded growth from callers that
//! never release and never expire, [`HANDLE_TABLE_MAX_SIZE`] caps the table
//! at 10,000 live entries with FIFO eviction of the oldest handle — mirroring
//! the TypeScript `usageCounts` map's `USAGE_MAP_MAX_SIZE` guard
//! (`packages/vaultkeeper/src/vault.ts`) exactly.
//!
//! ## Why `expires_at` must stay caller-supplied, not hardcoded
//!
//! There is an open product decision (issue #261) about custody of an
//! automation agent's signing key — an agent that signs non-interactively,
//! with no human present, over a long-lived identity. This policy
//! deliberately does **not** assume every handle belongs to a short,
//! human-approved, interactive session:
//!
//! - `expires_at` is **not** derived from "when did the approving human's
//!   session end" — there is no such concept here. It is bound to whatever
//!   lifetime the *caller* chose for the underlying token (`authorize()`
//!   passes the JWE's own `exp` claim, which `setup()`'s `ttl_minutes` fully
//!   controls, including very long TTLs for a long-lived automation
//!   identity).
//! - Refreshing a handle never requires an interactive re-prompt. A
//!   non-interactive caller re-authorizes by presenting its token again
//!   (`authorize()`), which is exactly how a long-lived, machine-driven
//!   caller with an unlimited or high `use_limit` keeps working — no human
//!   in the loop, no forced short expiry.
//! - Nothing in this table refuses to construct a handle with a distant
//!   `expires_at` or an unlimited `use_limit`. A long-lived, non-interactive
//!   holder (the automation-agent case from #261) is fully expressible with
//!   today's primitives; #261 only has to decide *how* such an identity is
//!   provisioned, not fight this table's lifetime model to do it.
//!
//! # Usage-limit accounting: single authority (AC5)
//!
//! JTI-level usage counting — how many times a given token has been
//! presented to `authorize()` — used to live in a bare
//! `HashMap<String, u64>` field directly on `VaultKeeper`
//! (`crates/vaultkeeper-core/src/vault.rs`, pre-#241). It now lives here
//! ([`HandleTable::current_usage`]/[`HandleTable::record_usage`]) alongside
//! per-handle expiry, so the handle table is the single place that
//! understands both "when does this token's use-budget run out" and "when
//! does the resulting handle stop being resolvable" — instead of two
//! separately-maintained data structures that could drift out of sync.
//!
//! **Process-global (TS) vs. per-instance (Rust) divergence.** The
//! TypeScript library's `usageCounts` (`packages/vaultkeeper/src/vault.ts`)
//! is a **module-level `Map`, shared by every `VaultKeeper` instance in the
//! process** (capped at 10,000 entries, oldest evicted first). This table is
//! **owned per `VaultKeeper` instance** — two independently-constructed
//! `VaultKeeper`s (Rust has no ambient module-global singleton idiom
//! equivalent to a TS top-level `const`) do not share usage counts or
//! handles. This divergence predates #241 (the pre-#241 `usage_counts` field
//! was already instance-scoped); this issue only relocates where the
//! bookkeeping lives, it does not change the scoping. Rust callers
//! (native CLI, WASM SDK) are expected to construct one `VaultKeeper` per
//! host process without hidden cross-instance sharing, so per-instance
//! scoping is the intentional, correct behavior here — see
//! `handle_table_usage_counts_are_not_shared_across_instances` below for a
//! test that pins this down.

use std::collections::{HashMap, VecDeque};
use std::fmt;

use zeroize::Zeroizing;

use crate::errors::VaultError;
use crate::types::{SigningClaims, VaultClaims};
use crate::util::time::now_secs;

/// Maximum number of live entries [`HandleTable`] (both the handle map and
/// the JTI usage-count map) will retain. When the cap is reached, the oldest
/// inserted entry is evicted (FIFO) to make room. Mirrors the TypeScript
/// `USAGE_MAP_MAX_SIZE` guard (`packages/vaultkeeper/src/vault.ts`) — this is
/// the defense-in-depth backstop against unbounded growth described in the
/// module docs, not the primary eviction mechanism (release/expiry/usage-limit
/// are).
pub const HANDLE_TABLE_MAX_SIZE: usize = 10_000;

/// Opaque handle identifier returned by [`HandleTable::insert_secret`] /
/// [`HandleTable::insert_signing`].
///
/// Carries no claims data itself — it is a bare, unguessable (UUID v4)
/// lookup key. **It is bearer capability material, not a public
/// identifier**: this table has no secondary check beyond a `HashMap`
/// lookup by id, so whoever presents a
/// `HandleId` can resolve its claims and read its secret (until the secret
/// is consumed) for as long as the handle stays live — mere possession is
/// sufficient, exactly like presenting the JWE token this handle was minted
/// from. Treat it with the same handling discipline: never log it or
/// otherwise expose it to an untrusted party, and pass it only across
/// trusted boundaries (e.g. the WASM FFI boundary within the same trust
/// domain, as `wasm_impl.rs` does). This deliberately differs from the
/// TypeScript `CapabilityToken` (`packages/vaultkeeper/src/identity/session.ts`),
/// whose unforgeability comes from JS object identity in a module-private
/// `WeakMap` rather than a value that can be copied or printed — there is no
/// equivalent "just don't expose the reference" guarantee for a stringly-typed
/// id crossing an FFI boundary, so the caller has to uphold it explicitly.
/// An id this table does not recognize (already released, evicted, or never
/// minted by this table) errors with [`VaultError::AuthorizationDenied`],
/// mirroring `validateCapabilityToken` rejecting a token from a different
/// `WeakMap`/module instance.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct HandleId(String);

impl HandleId {
    fn new() -> Self {
        Self(uuid::Uuid::new_v4().to_string())
    }

    /// The underlying opaque identifier string. Exposed so a host bridge
    /// (e.g. the WASM boundary) can carry it across an FFI boundary as a
    /// plain string. **This is bearer capability material, not a public
    /// identifier** (see the struct docs) — do not log it, persist it
    /// insecurely, or otherwise expose it outside a trusted boundary.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for HandleId {
    /// Renders the full id. Used deliberately by this module's own error
    /// messages (`unknown_handle_error`, the expiry branch of `ensure_live`)
    /// to name *which* handle was invalid/expired for the caller's own
    /// debugging — that is a reviewed, intentional call site, not the
    /// accidental-logging path `Debug` guards against below.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for HandleId {
    /// Redacted on purpose: `{:?}` is the common *accidental* logging path
    /// (`debug!("{:?}", handle)`, a bare `dbg!(handle)`, an auto-derived
    /// `Debug` on a containing struct). Printing only a short, non-redeemable
    /// prefix still lets log lines be correlated with each other without
    /// handing a log sink the bearer token itself.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let prefix = self.0.get(..8).unwrap_or(&self.0);
        write!(f, "HandleId({prefix}…)")
    }
}

impl From<HandleId> for String {
    fn from(id: HandleId) -> Self {
        id.0
    }
}

impl From<String> for HandleId {
    /// Reconstruct a `HandleId` from its opaque string form — used by a host
    /// bridge (e.g. the WASM boundary) that carried a `HandleId::as_str()`
    /// value across an FFI boundary and needs to look it up again. Does not
    /// validate that the string was ever actually minted by a
    /// [`HandleTable`] — an unrecognized value simply fails the table's own
    /// lookup with [`VaultError::AuthorizationDenied`].
    fn from(id: String) -> Self {
        Self(id)
    }
}

/// The claims a capability handle can wrap: either an ordinary secret's
/// [`VaultClaims`] or a signing key's [`SigningClaims`]. Mirrors the
/// TypeScript `StoredClaims` union (`packages/vaultkeeper/src/identity/session.ts`).
///
/// A [`StoredClaims::Secret`] entry's [`VaultClaims::val`] is always empty —
/// the real secret is held out-of-band in the handle's own `secret` field
/// (see [`HandleTable::read_secret`]), never inside `StoredClaims` itself, so
/// a caller that only needs metadata (`resolve_secret_claims`) can never
/// accidentally observe it.
#[derive(Debug, Clone)]
pub enum StoredClaims {
    /// Claims for an ordinary secret-access handle.
    Secret(VaultClaims),
    /// Claims for a signing-key handle. Carries only references (`kid`,
    /// `backend_ref`) — never key material.
    Signing(SigningClaims),
}

impl StoredClaims {
    /// Whether these are signing-key claims (as opposed to secret claims).
    #[must_use]
    pub fn is_signing(&self) -> bool {
        matches!(self, StoredClaims::Signing(_))
    }
}

fn wrong_kind_error(expected: &str, found: &str) -> VaultError {
    VaultError::AuthorizationDenied {
        message: format!(
            "This capability handle authorizes a {found}, not a {expected} — it cannot be used \
             for {expected} access. Use the {found} path instead."
        ),
    }
}

fn unknown_handle_error(id: &HandleId) -> VaultError {
    VaultError::AuthorizationDenied {
        message: format!(
            "Unknown or already-released capability handle: {id} (not created by this vault \
             instance, already released, or evicted)"
        ),
    }
}

struct HandleEntry {
    claims: StoredClaims,
    /// The one-time-readable secret. `None` once [`HandleTable::read_secret`]
    /// has consumed it, or always for a [`StoredClaims::Signing`] entry
    /// (which never carries a secret).
    secret: Option<Zeroizing<String>>,
    /// Unix-seconds absolute expiry. `None` means this handle carries no
    /// core-imposed expiry of its own (see the module-level "Why
    /// `expires_at` must stay caller-supplied" note) — eviction then relies
    /// on explicit release, usage-limit exhaustion, or the FIFO size cap.
    expires_at: Option<u64>,
}

/// Opaque capability-handle table. See the module docs for the full design
/// rationale (lifetime/eviction policy, signing-vs-secret discrimination,
/// usage-limit accounting).
#[derive(Default)]
pub struct HandleTable {
    entries: HashMap<HandleId, HandleEntry>,
    /// FIFO insertion order for `entries`, used only by the max-size
    /// backstop eviction.
    entry_order: VecDeque<HandleId>,
    /// JTI usage counts — the single accounting authority for a token's
    /// `use_limit` (AC5). See the module doc's "Usage-limit accounting"
    /// section for how this relates to per-handle expiry.
    usage_counts: HashMap<String, u64>,
    /// FIFO insertion order for `usage_counts`, used only by the max-size
    /// backstop eviction.
    usage_order: VecDeque<String>,
}

impl HandleTable {
    /// Create an empty handle table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The number of the token's `use_limit`-bounded presentations to
    /// `authorize()` recorded so far for `jti`, i.e. the count *before* the
    /// next call to [`HandleTable::record_usage`]. Returns `0` for a `jti`
    /// never seen before.
    #[must_use]
    pub fn current_usage(&self, jti: &str) -> u64 {
        self.usage_counts.get(jti).copied().unwrap_or(0)
    }

    /// Record one more presentation of `jti` and return the new count.
    ///
    /// Ported verbatim (semantics unchanged) from the pre-#241
    /// `VaultKeeper::usage_counts` field's read-then-increment pattern —
    /// `authorize()` already calls [`HandleTable::current_usage`] before
    /// `validate_claims`, then this, exactly as it did with the bare
    /// `HashMap` before. Bounded by [`HANDLE_TABLE_MAX_SIZE`] with FIFO
    /// eviction of the oldest tracked `jti` (see the module doc's
    /// process-global-vs-per-instance note for why this per-instance map
    /// still needs its own bound even though it is not shared globally).
    pub fn record_usage(&mut self, jti: &str) -> u64 {
        if !self.usage_counts.contains_key(jti) {
            if self.usage_counts.len() >= HANDLE_TABLE_MAX_SIZE
                && let Some(oldest) = self.usage_order.pop_front()
            {
                self.usage_counts.remove(&oldest);
            }
            self.usage_order.push_back(jti.to_string());
        }
        let new_usage = self.current_usage(jti) + 1;
        self.usage_counts.insert(jti.to_string(), new_usage);
        new_usage
    }

    /// Register a secret-access handle. `claims.val` is taken out into the
    /// handle's own one-time-readable secret storage — the stored
    /// [`StoredClaims::Secret`] always has an empty `val` — before being
    /// inserted, so nothing downstream of this call can observe the secret
    /// through the claims themselves.
    ///
    /// `expires_at` is caller-supplied (see the module docs for why this
    /// must not be hardcoded here) — `authorize()` passes the token's own
    /// `exp` claim.
    pub fn insert_secret(&mut self, mut claims: VaultClaims, expires_at: Option<u64>) -> HandleId {
        let secret = std::mem::take(&mut claims.val);
        self.insert(
            StoredClaims::Secret(claims),
            Some(Zeroizing::new(secret)),
            expires_at,
        )
    }

    /// Register a signing-key handle. Carries no secret — a signing-key
    /// handle's `read_secret` is always refused (see [`wrong_kind_error`]).
    pub fn insert_signing(&mut self, claims: SigningClaims, expires_at: Option<u64>) -> HandleId {
        self.insert(StoredClaims::Signing(claims), None, expires_at)
    }

    fn insert(
        &mut self,
        claims: StoredClaims,
        secret: Option<Zeroizing<String>>,
        expires_at: Option<u64>,
    ) -> HandleId {
        self.sweep_expired();
        if self.entries.len() >= HANDLE_TABLE_MAX_SIZE
            && let Some(oldest) = self.entry_order.pop_front()
        {
            self.entries.remove(&oldest);
        }
        let id = HandleId::new();
        self.entries.insert(
            id.clone(),
            HandleEntry {
                claims,
                secret,
                expires_at,
            },
        );
        self.entry_order.push_back(id.clone());
        id
    }

    /// Check the handle exists and has not expired, evicting it (and
    /// returning [`VaultError::TokenExpired`]) if it has just crossed its
    /// `expires_at`. Returns [`VaultError::AuthorizationDenied`] for an
    /// unrecognized id.
    fn ensure_live(&mut self, id: &HandleId) -> Result<(), VaultError> {
        let expired = match self.entries.get(id) {
            None => return Err(unknown_handle_error(id)),
            Some(entry) => entry.expires_at.is_some_and(|exp| now_secs() >= exp),
        };
        if expired {
            self.entries.remove(id);
            self.entry_order.retain(|existing| existing != id);
            return Err(VaultError::TokenExpired {
                message: format!("Capability handle {id} has expired"),
                can_refresh: false,
            });
        }
        Ok(())
    }

    /// Resolve non-secret claims for a fetch/exec/`getSecret`-style consumer
    /// (AC2 — "no secret egress"). Returns a clone of the stored
    /// [`VaultClaims`], whose `val` is always empty. Refuses a signing-key
    /// handle with [`VaultError::AuthorizationDenied`] (AC3).
    pub fn resolve_secret_claims(&mut self, id: &HandleId) -> Result<VaultClaims, VaultError> {
        self.ensure_live(id)?;
        // ensure_live just confirmed presence and non-expiry.
        let entry = self.entries.get(id).expect("checked live above");
        match &entry.claims {
            StoredClaims::Secret(claims) => Ok(claims.clone()),
            StoredClaims::Signing(_) => Err(wrong_kind_error("secret", "signing key")),
        }
    }

    /// Resolve claims for a `sign()`-style consumer. Refuses a secret handle
    /// with [`VaultError::AuthorizationDenied`] (AC3), mirroring the
    /// TypeScript `sign()`'s `isSigningClaims` check.
    pub fn resolve_signing_claims(&mut self, id: &HandleId) -> Result<SigningClaims, VaultError> {
        self.ensure_live(id)?;
        let entry = self.entries.get(id).expect("checked live above");
        match &entry.claims {
            StoredClaims::Signing(claims) => Ok(claims.clone()),
            StoredClaims::Secret(_) => Err(wrong_kind_error("signing key", "secret")),
        }
    }

    /// Read the raw secret behind `id` exactly once (AC2). A second call —
    /// or any call against a handle whose secret was already read — returns
    /// [`VaultError::AccessorConsumed`] (issue #236). Refuses a signing-key
    /// handle with [`VaultError::AuthorizationDenied`] (AC3): a signing key
    /// carries no secret and must never be readable this way.
    pub fn read_secret(&mut self, id: &HandleId) -> Result<Zeroizing<String>, VaultError> {
        self.ensure_live(id)?;
        let entry = self.entries.get_mut(id).expect("checked live above");
        if entry.claims.is_signing() {
            return Err(wrong_kind_error("secret", "signing key"));
        }
        entry
            .secret
            .take()
            .ok_or_else(|| VaultError::AccessorConsumed {
                message: format!(
                    "Secret for capability handle {id} has already been read; the one-time \
                 accessor is consumed"
                ),
            })
    }

    /// Explicitly release `id`, evicting it immediately regardless of
    /// expiry/usage state. Returns `true` if a handle was actually present
    /// and removed. This is the primary, cheap eviction path (see the module
    /// docs) — a caller that is done with a handle should call this rather
    /// than waiting on expiry or the size-cap backstop.
    pub fn release(&mut self, id: &HandleId) -> bool {
        self.entry_order.retain(|existing| existing != id);
        self.entries.remove(id).is_some()
    }

    /// Proactively evict every handle whose `expires_at` has passed. Returns
    /// the number of handles evicted.
    ///
    /// This is not required for correctness — every resolve/read method
    /// checks expiry lazily on its own — but lets a host that wants to bound
    /// memory more eagerly than "next access" do so (e.g. a CLI daemon
    /// loop's periodic tick).
    pub fn sweep_expired(&mut self) -> usize {
        let now = now_secs();
        let expired: Vec<HandleId> = self
            .entries
            .iter()
            .filter(|(_, entry)| entry.expires_at.is_some_and(|exp| now >= exp))
            .map(|(id, _)| id.clone())
            .collect();
        for id in &expired {
            self.entries.remove(id);
        }
        if !expired.is_empty() {
            self.entry_order.retain(|id| !expired.contains(id));
        }
        expired.len()
    }

    /// The number of live handles currently held (not including entries
    /// past their `expires_at` that haven't been swept/accessed yet).
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the table currently holds no handles.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::TrustTier;

    fn secret_claims(jti: &str, val: &str) -> VaultClaims {
        VaultClaims {
            jti: jti.to_string(),
            exp: now_secs() + 3600,
            iat: now_secs(),
            sub: "test-secret".to_string(),
            exe: "dev".to_string(),
            use_limit: None,
            tid: TrustTier::Dev,
            bkd: "file".to_string(),
            val: val.to_string(),
            reference: "test-secret".to_string(),
        }
    }

    fn signing_claims() -> SigningClaims {
        SigningClaims {
            kid: "kid-1".to_string(),
            backend_ref: "signing-key:test".to_string(),
        }
    }

    /// Regression test: `HandleId` is bearer capability material (see the
    /// struct docs) — mere possession redeems it, so the derived `Debug`
    /// impl this type used to have printed the full bearer id via the most
    /// common *accidental* logging path (`{:?}`, `dbg!(..)`, an
    /// auto-derived `Debug` on a containing struct), directly contradicting
    /// a "do not log it" handling requirement. `Display` is intentionally
    /// left showing the full id (this module's own error messages rely on
    /// it to name which handle failed) — only the accidental-logging path
    /// is guarded.
    #[test]
    fn handle_id_debug_output_does_not_reveal_the_full_bearer_id() {
        let mut table = HandleTable::new();
        let id = table.insert_secret(secret_claims("jti-1", "s3cret"), None);

        let debug_output = format!("{id:?}");
        assert_ne!(
            debug_output,
            id.as_str(),
            "Debug must not print the full bearer id verbatim"
        );
        assert!(
            !debug_output.contains(id.as_str()),
            "Debug output {debug_output:?} must not contain the full bearer id {}",
            id.as_str()
        );

        // Display remains the full id — used deliberately by this module's
        // own diagnostic error messages.
        assert_eq!(format!("{id}"), id.as_str());
    }

    #[test]
    fn insert_secret_strips_val_from_stored_claims() {
        let mut table = HandleTable::new();
        let id = table.insert_secret(secret_claims("jti-1", "s3cret"), None);
        let claims = table.resolve_secret_claims(&id).unwrap();
        assert_eq!(
            claims.val, "",
            "resolve_secret_claims must never egress the secret"
        );
        assert_eq!(claims.sub, "test-secret");
    }

    #[test]
    fn read_secret_returns_the_original_value_once() {
        let mut table = HandleTable::new();
        let id = table.insert_secret(secret_claims("jti-1", "s3cret"), None);
        let secret = table.read_secret(&id).unwrap();
        assert_eq!(secret.as_str(), "s3cret");
    }

    /// AC7: double-read of the one-time secret accessor.
    #[test]
    fn read_secret_twice_returns_accessor_consumed() {
        let mut table = HandleTable::new();
        let id = table.insert_secret(secret_claims("jti-1", "s3cret"), None);
        table.read_secret(&id).unwrap();
        let err = table.read_secret(&id).unwrap_err();
        assert!(
            matches!(err, VaultError::AccessorConsumed { .. }),
            "expected AccessorConsumed, got {err:?}"
        );
    }

    /// AC7: wrong-kind handle — a signing handle refuses secret-access paths.
    #[test]
    fn signing_handle_refuses_secret_reads() {
        let mut table = HandleTable::new();
        let id = table.insert_signing(signing_claims(), None);

        let err = table.read_secret(&id).unwrap_err();
        assert!(matches!(err, VaultError::AuthorizationDenied { .. }));

        let err = table.resolve_secret_claims(&id).unwrap_err();
        assert!(matches!(err, VaultError::AuthorizationDenied { .. }));
    }

    /// AC7: wrong-kind handle — a secret handle refuses the signing path.
    #[test]
    fn secret_handle_refuses_signing_resolution() {
        let mut table = HandleTable::new();
        let id = table.insert_secret(secret_claims("jti-1", "s3cret"), None);
        let err = table.resolve_signing_claims(&id).unwrap_err();
        assert!(matches!(err, VaultError::AuthorizationDenied { .. }));
    }

    #[test]
    fn resolve_signing_claims_returns_kid_and_backend_ref() {
        let mut table = HandleTable::new();
        let id = table.insert_signing(signing_claims(), None);
        let claims = table.resolve_signing_claims(&id).unwrap();
        assert_eq!(claims.kid, "kid-1");
        assert_eq!(claims.backend_ref, "signing-key:test");
    }

    /// AC7: expired handle.
    #[test]
    fn expired_handle_is_rejected_and_evicted() {
        let mut table = HandleTable::new();
        // expires_at in the past.
        let id = table.insert_secret(secret_claims("jti-1", "s3cret"), Some(now_secs() - 1));
        let err = table.resolve_secret_claims(&id).unwrap_err();
        assert!(matches!(err, VaultError::TokenExpired { .. }));
        // The expired handle was evicted as a side effect — it's now unknown,
        // not merely still-expired, proving AC4's "no unbounded growth".
        assert_eq!(table.len(), 0);
        let err = table.resolve_secret_claims(&id).unwrap_err();
        assert!(matches!(err, VaultError::AuthorizationDenied { .. }));
    }

    #[test]
    fn sweep_expired_evicts_only_expired_handles() {
        let mut table = HandleTable::new();
        // Insert the not-yet-expired entries first: `insert` lazily sweeps
        // expired entries before inserting, so an already-expired entry must
        // be inserted last to survive until the explicit `sweep_expired()`
        // call below (rather than being swept as a side effect of a later
        // `insert_secret` call).
        let live = table.insert_secret(secret_claims("jti-2", "b"), Some(now_secs() + 3600));
        let unbounded = table.insert_secret(secret_claims("jti-3", "c"), None);
        let expired = table.insert_secret(secret_claims("jti-1", "a"), Some(now_secs() - 1));

        let evicted = table.sweep_expired();
        assert_eq!(evicted, 1);
        assert_eq!(table.len(), 2);
        assert!(table.resolve_secret_claims(&expired).is_err());
        assert!(table.resolve_secret_claims(&live).is_ok());
        // A handle with no core-imposed expiry (the long-lived,
        // non-interactive automation case, AC4) survives a sweep untouched.
        assert!(table.resolve_secret_claims(&unbounded).is_ok());
    }

    #[test]
    fn release_evicts_immediately_regardless_of_expiry() {
        let mut table = HandleTable::new();
        let id = table.insert_secret(secret_claims("jti-1", "s3cret"), None);
        assert!(table.release(&id));
        assert!(
            !table.release(&id),
            "double release must not panic or re-evict"
        );
        let err = table.resolve_secret_claims(&id).unwrap_err();
        assert!(matches!(err, VaultError::AuthorizationDenied { .. }));
    }

    /// AC4: no unbounded growth — the FIFO size-cap backstop evicts the
    /// oldest handle once the table is full, even for handles that never
    /// expire and are never explicitly released (the pathological case a
    /// forgetful caller could otherwise trigger).
    #[test]
    fn table_evicts_oldest_handle_once_full() {
        let mut table = HandleTable::new();
        let first = table.insert_secret(secret_claims("jti-first", "a"), None);
        for i in 1..HANDLE_TABLE_MAX_SIZE {
            table.insert_secret(secret_claims(&format!("jti-{i}"), "x"), None);
        }
        assert_eq!(table.len(), HANDLE_TABLE_MAX_SIZE);
        // Table is now full; one more insert must evict the oldest (`first`).
        table.insert_secret(secret_claims("jti-overflow", "z"), None);
        assert_eq!(table.len(), HANDLE_TABLE_MAX_SIZE);
        let err = table.resolve_secret_claims(&first).unwrap_err();
        assert!(matches!(err, VaultError::AuthorizationDenied { .. }));
    }

    #[test]
    fn record_usage_increments_and_current_usage_reflects_it() {
        let mut table = HandleTable::new();
        assert_eq!(table.current_usage("jti-1"), 0);
        assert_eq!(table.record_usage("jti-1"), 1);
        assert_eq!(table.record_usage("jti-1"), 2);
        assert_eq!(table.current_usage("jti-1"), 2);
    }

    /// AC5: two independently-constructed handle tables (mirroring two
    /// independently-constructed `VaultKeeper` instances) do not share usage
    /// counts or handles — the intentional per-instance-vs-TS-process-global
    /// divergence documented in the module docs.
    #[test]
    fn handle_table_usage_counts_are_not_shared_across_instances() {
        let mut first = HandleTable::new();
        let mut second = HandleTable::new();
        first.record_usage("jti-shared");
        first.record_usage("jti-shared");
        assert_eq!(first.current_usage("jti-shared"), 2);
        assert_eq!(second.current_usage("jti-shared"), 0);

        let id = first.insert_secret(secret_claims("jti-shared", "s3cret"), None);
        assert!(second.resolve_secret_claims(&id).is_err());
    }
}
