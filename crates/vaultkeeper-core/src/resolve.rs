//! Profile resolution planner and materialization engine (issue #278).
//!
//! Turns a [`LoadedProfile`] (see [`crate::profile::loader`]) into a resolved
//! environment map, dispatching each entry to the right materialization
//! path:
//!
//! - `materialize: "secret"` retrieves the real value via
//!   [`SecretBackend::retrieve`].
//! - `materialize: "lease"` mints a VaultKeeper lease (JWE) by building the
//!   same [`crate::types::VaultClaims`] shape and calling
//!   [`crate::jwe::create_token`] — the exact mint primitive
//!   [`crate::vault::VaultKeeper::setup`] itself calls internally. This
//!   module deliberately does not go through the full `setup()` method: that
//!   method's executable-trust binding (Sigstore/TOFU verification of the
//!   *calling* executable, requiring a [`crate::backend::HostPlatform`]) is
//!   an orthogonal, one-time-per-invocation concern for whichever front end
//!   ends up driving profile resolution (e.g. a future `run` verb), not a
//!   per-entry concern of the resolver itself. Reusing the shared mint
//!   primitive directly keeps `resolve_profile` free of any `HostPlatform`
//!   dependency, matching the "must not spawn / must not touch a launcher"
//!   constraint below. A resolved lease's `exe` claim is bound to the `"dev"`
//!   sentinel (unverified) rather than a real executable hash, exactly as
//!   [`crate::vault::SetupOptions::skip_trust`] would produce.
//!
//! This is pure core logic over abstractions core already owns:
//!
//! - **Written against the [`SecretBackend`] trait object only.** The
//!   resolver never names a concrete backend type — [`ResolveOptions`] holds
//!   a `&dyn SecretBackend`, so any registered backend (including a future
//!   registry-reachable JS backend) resolves through the same code path.
//! - **All-or-nothing failure semantics.** [`resolve_profile`] resolves every
//!   entry into a scratch buffer first, and only builds the returned
//!   [`ResolvedEnv`] once every entry has succeeded. Any single entry's
//!   failure returns that error immediately — no partial map is ever
//!   returned, and the scratch buffer's already-resolved values are
//!   zeroized as it drops on the error path (each held in a
//!   [`zeroize::Zeroizing`] wrapper), so a failed entry cannot leave another
//!   entry's secret sitting resolved in memory or observable to a caller.
//! - **Does not spawn.** `resolve_profile` never touches
//!   [`crate::backend::HostPlatform::exec`] (in fact it takes no
//!   `HostPlatform` at all) — process launch is a separate, per-host
//!   concern left entirely to a future `run` verb.
//!
//! A `materialize: "lease"` entry backed by a `signingKey` source (a session
//! signing lease) is not yet implemented — see the epic
//! (issue #276)'s "session mint, presence-at-mint... (to be filed)" work
//! item — and is refused with [`VaultError::MaterializeModeUnsupported`],
//! naming both the entry and its `signingKey` source, rather than silently
//! no-oping or minting an incomplete claims shape.
//!
//! A `materialize: "lease"` entry with `requirePresenceAtMint: true` on a
//! `secret` source is refused the same way: [`ResolveOptions`] carries no
//! [`crate::backend::HostPlatform`] to actually prompt for presence at mint
//! time, so resolving such an entry would otherwise silently mint a
//! presence-less lease that claims a guarantee it never enforced.
//!
//! A `materialize: "secret"` (or `"lease"`) entry's `requirePresencePerUse`
//! is enforced via the shared [`crate::vault::enforce_presence_requirement`]
//! primitive — the same one [`crate::vault::VaultKeeper::setup`] and other
//! backend-touching operations use — called with
//! [`crate::backend::PresenceOperation::Read`] immediately before
//! [`SecretBackend::retrieve`]. A flagged entry against a non-qualifying
//! backend is refused before the backend is ever touched.
//!
//! A `materialize: "lease"` entry's minted `exe` claim is bound to a real,
//! caller-supplied [`ResolveOptions::executable_hash`] whenever the entry's
//! resolved trust tier is `Sigstore` or `Tofu` — binding an unverified
//! `"dev"` sentinel under a claimed-verified tier would be incoherent. An
//! entry resolving to such a tier with no `executable_hash` supplied is
//! refused rather than silently minting the incoherent pair; a `Dev`-tier
//! entry always keeps the `"dev"` sentinel regardless.
//!
//! A `materialize: "lease"` entry's `exp` computation ([`mint_secret_lease`])
//! is deliberately overflow-safe: `ttl_seconds` is capped at
//! [`LEASE_TTL_MAX_SECONDS`] and `now + ttl_seconds` uses `saturating_add`,
//! so neither an adversarial/malformed profile's huge `ttlSeconds` nor the
//! (never-`0`) defensive fallback ([`DEFENSIVE_DEFAULT_TTL_SECONDS`]) can
//! panic or mint an already-expired lease. The #277 loader itself now
//! rejects an explicit `ttlSeconds: 0` at load time; the resolver's fallback
//! is defense in depth for a `ProfileEntry` built by some other path.

use std::collections::HashMap;

use zeroize::Zeroizing;

use crate::backend::{PresenceOperation, SecretBackend};
use crate::errors::VaultError;
use crate::keys::KeyManager;
use crate::profile::loader::{EntrySource, LoadedProfile, ProfileEntry};
use crate::profile::types::MaterializeMode;
use crate::types::TrustTier;
use crate::vault::{build_and_mint_claims, enforce_presence_requirement};

/// A resolved environment: env-var name → resolved string value (either the
/// real secret, for `materialize: "secret"`, or a compact JWE lease string,
/// for `materialize: "lease"`).
pub type ResolvedEnv = HashMap<String, String>;

/// The dependencies [`resolve_profile`] needs to materialize a profile's
/// entries.
///
/// Deliberately narrow: a [`SecretBackend`] trait object (never a concrete
/// backend type) for `materialize: "secret"` retrieval, and a [`KeyManager`]
/// reference to mint `materialize: "lease"` JWEs. No
/// [`crate::backend::HostPlatform`] is required — resolution requires no
/// `HostPlatform` and never spawns a process (`retrieve`/`KeyManager` do
/// their own I/O, so resolution is not filesystem-free in general).
pub struct ResolveOptions<'a> {
    /// The active secret backend, used only through the [`SecretBackend`]
    /// trait — never named as a concrete type.
    pub backend: &'a dyn SecretBackend,
    /// The active key manager, used to mint a `materialize: "lease"` entry's
    /// JWE with the same current key `VaultKeeper::setup()` would use.
    pub key_manager: &'a KeyManager,
    /// A pre-verified executable identity hash to bind into a minted
    /// lease's `exe` claim, when the entry's resolved trust tier is
    /// `Sigstore` or `Tofu`. `resolve_profile` performs no executable-trust
    /// verification itself (see the module docs) — this is the caller's
    /// attestation that it already ran that verification (e.g. a future
    /// `run` verb, before invoking `resolve_profile`). `None` when no such
    /// verification has been performed; an entry whose resolved tier is
    /// `Sigstore`/`Tofu` is refused rather than minted with the `"dev"`
    /// sentinel in that case. Ignored for `Dev`-tier entries, which always
    /// keep the `"dev"` sentinel.
    pub executable_hash: Option<String>,
}

/// Resolve every entry of a loaded profile into a single environment map.
///
/// See the module docs for the all-or-nothing failure semantics and the
/// mint-path reuse rationale.
///
/// # Errors
/// Returns the first entry's resolution failure (in profile entry order).
/// On any error, no environment map is returned and no other entry's
/// resolved value is observable to the caller.
pub async fn resolve_profile(
    profile: &LoadedProfile,
    opts: &ResolveOptions<'_>,
) -> Result<ResolvedEnv, VaultError> {
    // A scratch buffer, not the final return value: each already-resolved
    // entry's value is held in a `Zeroizing` wrapper so that if a later
    // entry fails, the early `?` return drops `resolved` here — zeroizing
    // every value already resolved — before any of it is observable to the
    // caller. Only once every entry succeeds does the successful `Ok` arm
    // below convert this into the returned `ResolvedEnv`.
    let mut resolved: Vec<(String, Zeroizing<String>)> = Vec::with_capacity(profile.entries.len());

    for (name, entry) in &profile.entries {
        let value = resolve_entry(name, entry, opts).await?;
        resolved.push((name.clone(), Zeroizing::new(value)));
    }

    Ok(resolved
        .into_iter()
        .map(|(name, value)| (name, value.to_string()))
        .collect())
}

/// Resolve a single entry to its materialized string value.
async fn resolve_entry(
    name: &str,
    entry: &ProfileEntry,
    opts: &ResolveOptions<'_>,
) -> Result<String, VaultError> {
    match &entry.source {
        EntrySource::SigningKey(key_name) => {
            // The loader rejects `signingKey` + `materialize: "secret"` at
            // load time (a signing key's private material never leaves the
            // backend), so every signingKey entry that reaches here has
            // `materialize: "lease"` — a session signing lease. That mint
            // path (presence-at-mint, `kty: "signing-key"` claims shape) is
            // a distinct, not-yet-implemented work item (see the module
            // docs), so it is refused explicitly rather than silently
            // producing an incomplete/incorrect claims shape.
            Err(VaultError::MaterializeModeUnsupported {
                message: format!(
                    "Profile entry \"{name}\" (signingKey \"{key_name}\") requests a session \
                     signing lease, which resolve_profile does not yet support — this is a \
                     separate work item tracked by the environment-profiles epic (issue #276)."
                ),
                mode: "signing-key-lease".to_string(),
            })
        }
        EntrySource::Secret(secret_name) => {
            // requirePresenceAtMint on a secret-backed lease: resolve_profile
            // has no HostPlatform to actually prompt for presence at mint
            // time (see the module docs), so refuse rather than silently
            // minting a lease that claims a guarantee it never enforced.
            if entry.materialize == MaterializeMode::Lease && entry.require_presence_at_mint {
                return Err(VaultError::MaterializeModeUnsupported {
                    message: format!(
                        "Profile entry \"{name}\" (secret \"{secret_name}\") requests \
                         requirePresenceAtMint on a materialize: \"lease\" entry, but \
                         resolve_profile has no HostPlatform to prompt for presence at mint \
                         time — refusing rather than silently minting a presence-less lease."
                    ),
                    mode: "secret-lease-presence-at-mint".to_string(),
                });
            }

            enforce_presence_requirement(
                opts.backend,
                PresenceOperation::Read,
                Some(entry.require_presence_per_use),
            )
            .await?;

            let value = opts.backend.retrieve(secret_name).await?;
            match entry.materialize {
                MaterializeMode::Secret => Ok(value),
                MaterializeMode::Lease => mint_secret_lease(name, secret_name, &value, entry, opts),
            }
        }
    }
}

/// Hard cap (seconds) on the effective TTL a `materialize: "lease"` entry can
/// mint with here, regardless of what `ttlSeconds` requests. The #277 loader
/// does not itself cap a *secret*-backed lease's `ttlSeconds` (unlike a
/// `signingKey`-backed lease — see
/// `crate::profile::loader::SIGNING_LEASE_MAX_TTL_SECONDS`), so a malformed
/// or adversarial profile could otherwise request an astronomically large
/// (even `u64::MAX`) TTL. Capping here, before the `exp` computation, keeps
/// `now + ttl_seconds` (below) comfortably clear of `u64` overflow even
/// without the `saturating_add` — the `saturating_add` is defense in depth,
/// not a substitute for this cap. 30 days.
const LEASE_TTL_MAX_SECONDS: u64 = 30 * 24 * 60 * 60;

/// Defensive fallback applied only if a `materialize: "lease"` entry somehow
/// reaches this function with no resolved `ttlSeconds` at all. The #277
/// loader always resolves a `Secret` + `Lease` entry's `ttlSeconds` to `Some`
/// (either the profile's explicit value or the config `defaults.ttlMinutes`
/// fallback — see `ProfileEntry::ttl_seconds` and
/// `loader::resolve_ttl_seconds`), so this path should never actually
/// execute against a loader-produced profile. It must never be `0`: a
/// `0`-second TTL would silently mint an already-expired lease. Mirrors the
/// loader's session-signing-lease default TTL
/// (`crate::profile::loader::SIGNING_LEASE_DEFAULT_TTL_SECONDS`, 8h) as a
/// reasonable systemwide default in the absence of any config to fall back
/// to at this call site.
const DEFENSIVE_DEFAULT_TTL_SECONDS: u64 =
    crate::profile::loader::SIGNING_LEASE_DEFAULT_TTL_SECONDS;

/// Mint a `materialize: "lease"` entry's JWE, reusing the same claims-shape
/// and minting primitive ([`build_and_mint_claims`])
/// [`crate::vault::VaultKeeper::setup`] uses internally — see the module
/// docs for why the full `setup()` method (and its executable-trust binding)
/// is not called here.
fn mint_secret_lease(
    name: &str,
    secret_name: &str,
    value: &str,
    entry: &ProfileEntry,
    opts: &ResolveOptions<'_>,
) -> Result<String, VaultError> {
    let mut ttl_seconds = entry
        .ttl_seconds
        .unwrap_or(DEFENSIVE_DEFAULT_TTL_SECONDS)
        .min(LEASE_TTL_MAX_SECONDS);
    debug_assert_ne!(
        ttl_seconds, 0,
        "ttl_seconds must never be 0 here — the #277 loader now rejects an explicit \
         ttlSeconds: 0 at load time, so reaching 0 here would indicate a ProfileEntry built \
         by some other path"
    );
    // Defense in depth, matching the debug_assert above: a `0` here would
    // mint an already-expired lease in a release build, where the assert is
    // compiled out.
    if ttl_seconds == 0 {
        ttl_seconds = DEFENSIVE_DEFAULT_TTL_SECONDS;
    }

    let tier = entry.min_trust.to_trust_tier();
    // The `exe` claim must not carry the unverified `"dev"` sentinel under a
    // trust tier that claims Sigstore/TOFU verification — that pairing is
    // incoherent (a claimed-verified tier with an admittedly-unverified
    // executable). resolve_profile performs no executable-trust
    // verification itself, so the only way to mint a coherent Sigstore/Tofu
    // lease is for the caller to supply an already-verified hash.
    let exe = match tier {
        TrustTier::Dev => "dev".to_string(),
        TrustTier::Sigstore | TrustTier::Tofu => match &opts.executable_hash {
            Some(hash) => hash.clone(),
            None => {
                return Err(VaultError::ExecutableTrustRequired {
                    message: format!(
                        "Profile entry \"{name}\" (secret \"{secret_name}\") resolves to trust \
                         tier {tier:?}, but resolve_profile was given no executable_hash to bind \
                         — minting a lease with an unverified \"dev\" exe marker under a \
                         Sigstore/TOFU trust tier would be incoherent. Supply \
                         ResolveOptions::executable_hash (a pre-verified executable identity) or \
                         lower the entry's minTrust to \"unverified\"."
                    ),
                    reason: crate::errors::ExecutableTrustRequiredReason::MissingChoice,
                });
            }
        },
    };

    let now = crate::util::time::now_secs();
    // `saturating_add` rather than `+`: `now` plus an (already capped, but
    // defense-in-depth) `ttl_seconds` must never panic on overflow (debug
    // builds) or silently wrap into a past `exp` (release builds) — both
    // would mint a lease that is either broken or, worse, already expired
    // the instant it's minted.
    let exp = now.saturating_add(ttl_seconds);

    build_and_mint_claims(
        opts.key_manager,
        secret_name,
        value,
        now,
        exp,
        exe,
        entry.use_limit,
        tier,
        opts.backend.backend_type().to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::InMemoryBackend;
    use crate::jwe::decrypt_token;
    use crate::profile::loader::{ProfileDefaults, load_profile_from_str};
    use crate::profile::types::MinTrust;
    use crate::types::TrustTier;
    use assert_matches::assert_matches;
    use std::sync::Mutex;

    fn defaults() -> ProfileDefaults {
        ProfileDefaults {
            ttl_seconds: 3600,
            trust_tier: TrustTier::Dev,
        }
    }

    fn key_manager() -> KeyManager {
        let mut km = KeyManager::new();
        km.init().unwrap();
        km
    }

    async fn seeded_backend(entries: &[(&str, &str)]) -> InMemoryBackend {
        let backend = InMemoryBackend::new();
        for (id, value) in entries {
            backend.store(id, value).await.unwrap();
        }
        backend
    }

    // --- AC1: mixed-rung profile resolves both a real secret and a
    // --- decryptable JWE lease into one map ---

    #[tokio::test]
    async fn resolves_a_mixed_rung_profile_to_one_map_with_a_real_secret_and_a_decryptable_lease() {
        let json = r#"{
            "version": 1, "name": "mixed",
            "entries": {
                "GITHUB_TOKEN": { "secret": "github-pat", "materialize": "secret" },
                "VK_DB_CREDENTIAL": {
                    "secret": "prod-db-password", "materialize": "lease",
                    "minTrust": "sigstore", "ttlSeconds": 900, "useLimit": 5
                }
            }
        }"#;
        let profile = load_profile_from_str(json, &defaults()).unwrap();
        let backend = seeded_backend(&[
            ("github-pat", "ghp_realtoken"),
            ("prod-db-password", "s3cr3t-db-pw"),
        ])
        .await;
        let km = key_manager();
        let opts = ResolveOptions {
            backend: &backend,
            key_manager: &km,
            // The entry's minTrust ("sigstore") requires a verified
            // executable hash to mint a coherent lease — see the
            // exe/tid trust-seam tests below for the refusal without one.
            executable_hash: Some("verified-caller-hash".to_string()),
        };

        let resolved = resolve_profile(&profile, &opts).await.unwrap();
        assert_eq!(resolved.len(), 2);

        // materialize: "secret" -> the real value, verbatim.
        assert_eq!(resolved.get("GITHUB_TOKEN").unwrap(), "ghp_realtoken");

        // materialize: "lease" -> a decryptable JWE whose claims match the
        // entry's policy and the retrieved secret value.
        let lease = resolved.get("VK_DB_CREDENTIAL").unwrap();
        assert_ne!(
            lease, "s3cr3t-db-pw",
            "lease must not be the plaintext secret"
        );
        let current_key = km.get_current_key().unwrap();
        let claims = decrypt_token(&current_key.key, lease).unwrap();
        assert_eq!(claims.sub, "prod-db-password");
        assert_eq!(claims.val.as_deref(), Some("s3cr3t-db-pw"));
        assert_eq!(claims.tid, TrustTier::Sigstore);
        assert_eq!(claims.exe, "verified-caller-hash");
        assert_eq!(claims.use_limit, Some(5));
        assert_eq!(claims.exp, claims.iat + 900);
    }

    // --- AC2: all-or-nothing failure on a mid-profile resolution error ---

    /// A `SecretBackend` that wraps an [`InMemoryBackend`] and records every
    /// id passed to `retrieve()`, in call order. Used to prove
    /// `resolve_profile` genuinely short-circuits on a failing entry — i.e.
    /// it never even *attempts* to resolve a later entry — rather than
    /// merely relying on the `Result` signature to withhold a partial map
    /// (which would be true even of a resolver that kept resolving every
    /// entry and only discarded the results at the end).
    struct SpyBackend {
        inner: InMemoryBackend,
        retrieve_calls: Mutex<Vec<String>>,
        /// When `true`, this backend reports `presence_per_use: true` for
        /// every operation — used by the requirePresencePerUse tests below
        /// to model a qualifying backend.
        presence_capable: bool,
    }

    impl SpyBackend {
        fn new() -> Self {
            Self {
                inner: InMemoryBackend::new(),
                retrieve_calls: Mutex::new(Vec::new()),
                presence_capable: false,
            }
        }

        fn new_presence_capable() -> Self {
            Self {
                inner: InMemoryBackend::new(),
                retrieve_calls: Mutex::new(Vec::new()),
                presence_capable: true,
            }
        }

        fn retrieve_calls(&self) -> Vec<String> {
            self.retrieve_calls.lock().expect("lock poisoned").clone()
        }
    }

    #[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
    #[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
    impl SecretBackend for SpyBackend {
        fn backend_type(&self) -> &str {
            self.inner.backend_type()
        }

        fn display_name(&self) -> &str {
            self.inner.display_name()
        }

        async fn is_available(&self) -> bool {
            self.inner.is_available().await
        }

        async fn store(&self, id: &str, secret: &str) -> Result<(), VaultError> {
            self.inner.store(id, secret).await
        }

        async fn retrieve(&self, id: &str) -> Result<String, VaultError> {
            self.retrieve_calls
                .lock()
                .expect("lock poisoned")
                .push(id.to_string());
            self.inner.retrieve(id).await
        }

        async fn delete(&self, id: &str) -> Result<(), VaultError> {
            self.inner.delete(id).await
        }

        async fn exists(&self, id: &str) -> Result<bool, VaultError> {
            self.inner.exists(id).await
        }

        fn as_presence_capable(&self) -> Option<&dyn crate::backend::PresenceCapableBackend> {
            if self.presence_capable {
                Some(self)
            } else {
                None
            }
        }
    }

    #[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
    #[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
    impl crate::backend::PresenceCapableBackend for SpyBackend {
        async fn get_capabilities(
            &self,
        ) -> Result<crate::backend::BackendCapabilities, VaultError> {
            Ok(crate::backend::BackendCapabilities {
                presence_per_use: true,
                presence_enforced_operations: None,
            })
        }
    }

    #[tokio::test]
    async fn a_failing_entry_aborts_the_whole_call_with_no_partial_env_map_observable() {
        let json = r#"{
            "version": 1, "name": "mixed",
            "entries": {
                "ONE": { "secret": "one", "materialize": "secret" },
                "TWO": { "secret": "two", "materialize": "secret" },
                "THREE": { "secret": "missing", "materialize": "secret" },
                "FOUR": { "secret": "four", "materialize": "secret" }
            }
        }"#;
        let profile = load_profile_from_str(json, &defaults()).unwrap();
        // "missing" is deliberately never stored, so entry THREE fails to
        // resolve while ONE, TWO, and FOUR would all succeed if attempted.
        let backend = SpyBackend::new();
        backend.store("one", "value-one").await.unwrap();
        backend.store("two", "value-two").await.unwrap();
        backend.store("four", "value-four").await.unwrap();
        let km = key_manager();
        let opts = ResolveOptions {
            backend: &backend,
            key_manager: &km,
            executable_hash: None,
        };

        let err = resolve_profile(&profile, &opts).await.unwrap_err();
        assert_matches!(err, VaultError::SecretNotFound { .. });

        // Genuine short-circuit, not merely "no `Ok` value returned": the
        // resolver must never even have attempted FOUR (the entry after the
        // failing THREE) — proving resolution stops at the first failure
        // rather than resolving everything and discarding the results.
        assert_eq!(
            backend.retrieve_calls(),
            vec!["one", "two", "missing"],
            "resolution must short-circuit at the failing entry and never \
             attempt a later entry"
        );
    }

    // --- AC3: exercised against InMemoryBackend, no process/launcher
    // --- involved ---

    #[tokio::test]
    async fn resolves_against_in_memory_backend_with_no_process_or_launcher_involved() {
        let json = r#"{
            "version": 1, "name": "decoupled",
            "entries": { "TOKEN": { "secret": "s", "materialize": "secret" } }
        }"#;
        let profile = load_profile_from_str(json, &defaults()).unwrap();
        // `InMemoryBackend` is a concrete, non-launcher-backed
        // `SecretBackend` impl; `ResolveOptions` never mentions a
        // `HostPlatform`, `Command`, or any process type, demonstrating
        // `resolve_profile` is decoupled from both a concrete backend type
        // and any launcher.
        let backend = seeded_backend(&[("s", "the-secret-value")]).await;
        let km = key_manager();
        let opts = ResolveOptions {
            backend: &backend,
            key_manager: &km,
            executable_hash: None,
        };

        let resolved = resolve_profile(&profile, &opts).await.unwrap();
        assert_eq!(resolved.get("TOKEN").unwrap(), "the-secret-value");
    }

    // --- Overflow-safe lease expiry: a huge ttlSeconds must not panic and
    // --- must not produce an already-expired lease ---

    #[tokio::test]
    async fn a_huge_ttl_seconds_neither_panics_nor_produces_an_already_expired_lease() {
        // The #277 loader does not cap a secret-backed lease's ttlSeconds
        // (unlike a signingKey-backed one), so this huge value reaches
        // resolve_profile unmodified — regression coverage for an unchecked
        // `now + ttl_seconds` add, which panics in debug and wraps to a past
        // `exp` in release.
        let json = format!(
            r#"{{
                "version": 1, "name": "overflow",
                "entries": {{
                    "HUGE": {{ "secret": "s", "materialize": "lease", "ttlSeconds": {} }}
                }}
            }}"#,
            u64::MAX
        );
        let profile = load_profile_from_str(&json, &defaults()).unwrap();
        let backend = seeded_backend(&[("s", "the-secret-value")]).await;
        let km = key_manager();
        let opts = ResolveOptions {
            backend: &backend,
            key_manager: &km,
            executable_hash: None,
        };

        // Must not panic (this call alone is the overflow regression check).
        let resolved = resolve_profile(&profile, &opts).await.unwrap();

        let lease = resolved.get("HUGE").unwrap();
        let current_key = km.get_current_key().unwrap();
        let claims = decrypt_token(&current_key.key, lease).unwrap();
        assert!(
            claims.exp > claims.iat,
            "an astronomically large requested ttlSeconds must still mint a \
             lease with exp strictly after iat, never an already-expired one"
        );
    }

    // --- Default TTL fallback must never be 0 ---

    #[tokio::test]
    async fn a_lease_entry_with_no_resolved_ttl_seconds_falls_back_to_a_nonzero_default() {
        // Bypasses the loader (which always resolves ttlSeconds to Some for
        // a Secret + Lease entry) to exercise mint_secret_lease's own
        // defensive fallback directly, proving it is a sane non-zero default
        // rather than the previous `unwrap_or(0)` — a 0-second TTL would
        // silently mint an already-expired lease.
        let profile = LoadedProfile {
            version: 1,
            name: "no-ttl".to_string(),
            entries: vec![(
                "NO_TTL".to_string(),
                ProfileEntry {
                    source: EntrySource::Secret("s".to_string()),
                    materialize: MaterializeMode::Lease,
                    min_trust: MinTrust::Unverified,
                    ttl_seconds: None,
                    use_limit: None,
                    require_presence_per_use: false,
                    require_presence_at_mint: false,
                },
            )],
        };
        let backend = seeded_backend(&[("s", "the-secret-value")]).await;
        let km = key_manager();
        let opts = ResolveOptions {
            backend: &backend,
            key_manager: &km,
            executable_hash: None,
        };

        let resolved = resolve_profile(&profile, &opts).await.unwrap();
        let lease = resolved.get("NO_TTL").unwrap();
        let current_key = km.get_current_key().unwrap();
        let claims = decrypt_token(&current_key.key, lease).unwrap();
        assert_eq!(
            claims.exp - claims.iat,
            DEFENSIVE_DEFAULT_TTL_SECONDS,
            "an entry reaching mint_secret_lease with no ttlSeconds must fall \
             back to a sane non-zero default, never 0"
        );
        assert_ne!(DEFENSIVE_DEFAULT_TTL_SECONDS, 0);
    }

    // --- Not-yet-supported signingKey + lease path is refused, not
    // --- silently mishandled ---

    #[tokio::test]
    async fn signing_key_lease_entries_are_refused_as_not_yet_supported() {
        let json = r#"{
            "version": 1, "name": "signing",
            "entries": { "SESSION": { "signingKey": "release-signer", "materialize": "lease" } }
        }"#;
        let profile = load_profile_from_str(json, &defaults()).unwrap();
        let backend = InMemoryBackend::new();
        let km = key_manager();
        let opts = ResolveOptions {
            backend: &backend,
            key_manager: &km,
            executable_hash: None,
        };

        let err = resolve_profile(&profile, &opts).await.unwrap_err();
        assert_matches!(
            err,
            VaultError::MaterializeModeUnsupported { ref message, .. }
                if message.contains("SESSION") && message.contains("release-signer")
        );
    }

    // --- Item 2: requirePresenceAtMint on a secret-backed lease is refused,
    // --- not silently minted presence-less ---

    #[tokio::test]
    async fn require_presence_at_mint_on_a_secret_backed_lease_is_refused() {
        let json = r#"{
            "version": 1, "name": "p",
            "entries": {
                "DB_LEASE": {
                    "secret": "prod-db-password", "materialize": "lease",
                    "requirePresenceAtMint": true
                }
            }
        }"#;
        let profile = load_profile_from_str(json, &defaults()).unwrap();
        let backend = seeded_backend(&[("prod-db-password", "s3cr3t")]).await;
        let km = key_manager();
        let opts = ResolveOptions {
            backend: &backend,
            key_manager: &km,
            executable_hash: None,
        };

        let err = resolve_profile(&profile, &opts).await.unwrap_err();
        assert_matches!(
            err,
            VaultError::MaterializeModeUnsupported { ref message, .. }
                if message.contains("DB_LEASE") && message.contains("prod-db-password")
        );
    }

    // --- Item 1: requirePresencePerUse is enforced before retrieve ---

    #[tokio::test]
    async fn require_presence_per_use_refuses_before_retrieve_when_backend_is_not_capable() {
        let json = r#"{
            "version": 1, "name": "p",
            "entries": {
                "TOKEN": {
                    "secret": "s", "materialize": "secret", "requirePresencePerUse": true
                }
            }
        }"#;
        let profile = load_profile_from_str(json, &defaults()).unwrap();
        let backend = SpyBackend::new();
        backend.store("s", "v").await.unwrap();
        let km = key_manager();
        let opts = ResolveOptions {
            backend: &backend,
            key_manager: &km,
            executable_hash: None,
        };

        let err = resolve_profile(&profile, &opts).await.unwrap_err();
        assert_matches!(err, VaultError::NotCapable { .. });
        assert!(
            backend.retrieve_calls().is_empty(),
            "retrieve must never be attempted when presence enforcement refuses"
        );
    }

    #[tokio::test]
    async fn require_presence_per_use_permits_retrieve_when_backend_is_capable() {
        let json = r#"{
            "version": 1, "name": "p",
            "entries": {
                "TOKEN": {
                    "secret": "s", "materialize": "secret", "requirePresencePerUse": true
                }
            }
        }"#;
        let profile = load_profile_from_str(json, &defaults()).unwrap();
        let backend = SpyBackend::new_presence_capable();
        backend.store("s", "v").await.unwrap();
        let km = key_manager();
        let opts = ResolveOptions {
            backend: &backend,
            key_manager: &km,
            executable_hash: None,
        };

        let resolved = resolve_profile(&profile, &opts).await.unwrap();
        assert_eq!(resolved.get("TOKEN").unwrap(), "v");
        assert_eq!(backend.retrieve_calls(), vec!["s"]);
    }

    // --- Item 5: exe/tid trust seam ---

    #[tokio::test]
    async fn sigstore_tier_lease_without_executable_hash_is_refused() {
        let json = r#"{
            "version": 1, "name": "p",
            "entries": {
                "K": { "secret": "s", "materialize": "lease", "minTrust": "sigstore" }
            }
        }"#;
        let profile = load_profile_from_str(json, &defaults()).unwrap();
        let backend = seeded_backend(&[("s", "v")]).await;
        let km = key_manager();
        let opts = ResolveOptions {
            backend: &backend,
            key_manager: &km,
            executable_hash: None,
        };

        let err = resolve_profile(&profile, &opts).await.unwrap_err();
        assert_matches!(
            err,
            VaultError::ExecutableTrustRequired { ref message, .. } if message.contains('K')
        );
    }

    #[tokio::test]
    async fn tofu_tier_lease_without_executable_hash_is_refused() {
        let json = r#"{
            "version": 1, "name": "p",
            "entries": {
                "K": { "secret": "s", "materialize": "lease", "minTrust": "registry" }
            }
        }"#;
        let profile = load_profile_from_str(json, &defaults()).unwrap();
        let backend = seeded_backend(&[("s", "v")]).await;
        let km = key_manager();
        let opts = ResolveOptions {
            backend: &backend,
            key_manager: &km,
            executable_hash: None,
        };

        let err = resolve_profile(&profile, &opts).await.unwrap_err();
        assert_matches!(err, VaultError::ExecutableTrustRequired { .. });
    }

    #[tokio::test]
    async fn sigstore_tier_lease_with_executable_hash_binds_it_into_the_exe_claim() {
        let json = r#"{
            "version": 1, "name": "p",
            "entries": {
                "K": { "secret": "s", "materialize": "lease", "minTrust": "sigstore" }
            }
        }"#;
        let profile = load_profile_from_str(json, &defaults()).unwrap();
        let backend = seeded_backend(&[("s", "v")]).await;
        let km = key_manager();
        let opts = ResolveOptions {
            backend: &backend,
            key_manager: &km,
            executable_hash: Some("verified-hash".to_string()),
        };

        let resolved = resolve_profile(&profile, &opts).await.unwrap();
        let current_key = km.get_current_key().unwrap();
        let claims = decrypt_token(&current_key.key, resolved.get("K").unwrap()).unwrap();
        assert_eq!(claims.tid, TrustTier::Sigstore);
        assert_eq!(claims.exe, "verified-hash");
    }

    #[tokio::test]
    async fn dev_tier_lease_keeps_the_dev_marker_even_when_executable_hash_is_supplied() {
        let json = r#"{
            "version": 1, "name": "p",
            "entries": {
                "K": { "secret": "s", "materialize": "lease", "minTrust": "unverified" }
            }
        }"#;
        let profile = load_profile_from_str(json, &defaults()).unwrap();
        let backend = seeded_backend(&[("s", "v")]).await;
        let km = key_manager();
        let opts = ResolveOptions {
            backend: &backend,
            key_manager: &km,
            // A caller-supplied hash must not leak into a Dev-tier lease's
            // exe claim — Dev always keeps the "dev" sentinel.
            executable_hash: Some("verified-hash".to_string()),
        };

        let resolved = resolve_profile(&profile, &opts).await.unwrap();
        let current_key = km.get_current_key().unwrap();
        let claims = decrypt_token(&current_key.key, resolved.get("K").unwrap()).unwrap();
        assert_eq!(claims.tid, TrustTier::Dev);
        assert_eq!(claims.exe, "dev");
    }

    #[tokio::test]
    async fn min_trust_matrix_flows_through_to_the_minted_tid_and_exe() {
        let json = r#"{
            "version": 1, "name": "p",
            "entries": {
                "REG": { "secret": "a", "materialize": "lease", "minTrust": "registry" },
                "UNV": { "secret": "b", "materialize": "lease", "minTrust": "unverified" },
                "DEF": { "secret": "c", "materialize": "lease" }
            }
        }"#;
        // `defaults()` uses TrustTier::Dev, so the DEF entry (omitted
        // minTrust) resolves to Dev via the profile/config default.
        let profile = load_profile_from_str(json, &defaults()).unwrap();
        let backend = seeded_backend(&[("a", "va"), ("b", "vb"), ("c", "vc")]).await;
        let km = key_manager();
        let opts = ResolveOptions {
            backend: &backend,
            key_manager: &km,
            executable_hash: Some("verified-hash".to_string()),
        };

        let resolved = resolve_profile(&profile, &opts).await.unwrap();
        let current_key = km.get_current_key().unwrap();

        let reg_claims = decrypt_token(&current_key.key, resolved.get("REG").unwrap()).unwrap();
        assert_eq!(reg_claims.tid, TrustTier::Tofu);
        assert_eq!(reg_claims.exe, "verified-hash");

        let unv_claims = decrypt_token(&current_key.key, resolved.get("UNV").unwrap()).unwrap();
        assert_eq!(unv_claims.tid, TrustTier::Dev);
        assert_eq!(unv_claims.exe, "dev");

        let def_claims = decrypt_token(&current_key.key, resolved.get("DEF").unwrap()).unwrap();
        assert_eq!(def_claims.tid, TrustTier::Dev);
        assert_eq!(def_claims.exe, "dev");
    }

    // --- Coverage additions ---

    #[tokio::test]
    async fn zero_entry_profile_resolves_to_an_empty_map_with_no_backend_calls() {
        let json = r#"{ "version": 1, "name": "empty", "entries": {} }"#;
        let profile = load_profile_from_str(json, &defaults()).unwrap();
        let backend = SpyBackend::new();
        let km = key_manager();
        let opts = ResolveOptions {
            backend: &backend,
            key_manager: &km,
            executable_hash: None,
        };

        let resolved = resolve_profile(&profile, &opts).await.unwrap();
        assert!(resolved.is_empty());
        // No entry means the loop body never runs at all, so neither
        // `SecretBackend::retrieve` nor `KeyManager::get_current_key` (which
        // is only ever reached from within that loop, via
        // `mint_secret_lease`) is ever called.
        assert!(backend.retrieve_calls().is_empty());
    }

    #[tokio::test]
    async fn get_current_key_failure_propagates_from_resolve_profile() {
        let json = r#"{
            "version": 1, "name": "p",
            "entries": { "K": { "secret": "s", "materialize": "lease" } }
        }"#;
        let profile = load_profile_from_str(json, &defaults()).unwrap();
        let backend = seeded_backend(&[("s", "v")]).await;
        // Deliberately uninitialized — `get_current_key()` fails.
        let km = KeyManager::new();
        let opts = ResolveOptions {
            backend: &backend,
            key_manager: &km,
            executable_hash: None,
        };

        let err = resolve_profile(&profile, &opts).await.unwrap_err();
        assert_matches!(err, VaultError::Other(ref message) if message.contains("not initialized"));
    }

    #[tokio::test]
    async fn loader_default_ttl_flows_end_to_end_through_the_resolver() {
        let config_defaults = ProfileDefaults {
            ttl_seconds: 3600,
            trust_tier: TrustTier::Dev,
        };
        let json = r#"{
            "version": 1, "name": "p",
            "entries": { "K": { "secret": "s", "materialize": "lease" } }
        }"#;
        let profile = load_profile_from_str(json, &config_defaults).unwrap();
        let backend = seeded_backend(&[("s", "v")]).await;
        let km = key_manager();
        let opts = ResolveOptions {
            backend: &backend,
            key_manager: &km,
            executable_hash: None,
        };

        let resolved = resolve_profile(&profile, &opts).await.unwrap();
        let current_key = km.get_current_key().unwrap();
        let claims = decrypt_token(&current_key.key, resolved.get("K").unwrap()).unwrap();
        assert_eq!(claims.exp - claims.iat, 3600);
    }
}
