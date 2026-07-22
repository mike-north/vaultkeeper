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
//! item — and returns [`VaultError::Other`] naming the entry rather than
//! silently no-oping or minting an incomplete claims shape.

use std::collections::HashMap;

use zeroize::Zeroizing;

use crate::backend::SecretBackend;
use crate::errors::VaultError;
use crate::jwe::{CreateTokenOptions, create_token};
use crate::keys::KeyManager;
use crate::profile::loader::{EntrySource, LoadedProfile, ProfileEntry};
use crate::profile::types::MaterializeMode;
use crate::types::VaultClaims;

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
/// [`crate::backend::HostPlatform`] is required — resolution never spawns a
/// process and never touches the filesystem.
pub struct ResolveOptions<'a> {
    /// The active secret backend, used only through the [`SecretBackend`]
    /// trait — never named as a concrete type.
    pub backend: &'a dyn SecretBackend,
    /// The active key manager, used to mint a `materialize: "lease"` entry's
    /// JWE with the same current key `VaultKeeper::setup()` would use.
    pub key_manager: &'a KeyManager,
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
        let value = resolve_entry(entry, opts).await?;
        resolved.push((name.clone(), Zeroizing::new(value)));
    }

    Ok(resolved
        .into_iter()
        .map(|(name, value)| (name, value.to_string()))
        .collect())
}

/// Resolve a single entry to its materialized string value.
async fn resolve_entry(
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
            Err(VaultError::Other(format!(
                "Profile entry resolution for signingKey \"{key_name}\" (session signing lease) \
                 is not yet supported by resolve_profile — this is a separate work item tracked \
                 by the environment-profiles epic (issue #276)."
            )))
        }
        EntrySource::Secret(secret_name) => {
            let value = opts.backend.retrieve(secret_name).await?;
            match entry.materialize {
                MaterializeMode::Secret => Ok(value),
                MaterializeMode::Lease => mint_secret_lease(secret_name, &value, entry, opts),
            }
        }
    }
}

/// Mint a `materialize: "lease"` entry's JWE, reusing the same claims shape
/// and [`create_token`] primitive [`crate::vault::VaultKeeper::setup`] uses
/// internally — see the module docs for why the full `setup()` method (and
/// its executable-trust binding) is not called here.
fn mint_secret_lease(
    secret_name: &str,
    value: &str,
    entry: &ProfileEntry,
    opts: &ResolveOptions<'_>,
) -> Result<String, VaultError> {
    // The loader always resolves a `Secret` + `Lease` entry's `ttlSeconds`
    // to `Some` (either the profile's explicit value or a config/defaults
    // fallback) — see `ProfileEntry::ttl_seconds` and
    // `loader::resolve_ttl_seconds`. `unwrap_or(0)` is a defensive fallback
    // only; it should never be exercised in practice.
    let ttl_seconds = entry.ttl_seconds.unwrap_or(0);
    let now = crate::util::time::now_secs();

    let claims = VaultClaims {
        jti: uuid::Uuid::new_v4().to_string(),
        exp: now + ttl_seconds,
        iat: now,
        sub: secret_name.to_string(),
        // Unverified sentinel — profile resolution does not perform
        // executable-trust binding; see the module docs.
        exe: "dev".to_string(),
        use_limit: entry.use_limit,
        tid: entry.min_trust.to_trust_tier(),
        bkd: Some(opts.backend.backend_type().to_string()),
        val: Some(value.to_string()),
        reference: secret_name.to_string(),
        kty: None,
        kid: None,
        kgen: None,
        pres: None,
    };

    let current_key = opts.key_manager.get_current_key()?;
    create_token(
        &current_key.key,
        &claims,
        &CreateTokenOptions {
            kid: Some(current_key.id.clone()),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::InMemoryBackend;
    use crate::jwe::decrypt_token;
    use crate::profile::loader::{ProfileDefaults, load_profile_from_str};
    use crate::types::TrustTier;
    use assert_matches::assert_matches;

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
        assert_eq!(claims.use_limit, Some(5));
        assert_eq!(claims.exp, claims.iat + 900);
    }

    // --- AC2: all-or-nothing failure on a mid-profile resolution error ---

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
        // resolve while ONE, TWO, and FOUR would all succeed.
        let backend = seeded_backend(&[
            ("one", "value-one"),
            ("two", "value-two"),
            ("four", "value-four"),
        ])
        .await;
        let km = key_manager();
        let opts = ResolveOptions {
            backend: &backend,
            key_manager: &km,
        };

        let err = resolve_profile(&profile, &opts).await.unwrap_err();
        assert_matches!(err, VaultError::SecretNotFound { .. });
        // The all-or-nothing contract is that `resolve_profile` never
        // returns anything but `Err` here — there is no partial `Ok(map)`
        // value to inspect, so the absence of a returned map (enforced by
        // the function's `Result<ResolvedEnv, VaultError>` signature and
        // this `unwrap_err()`) is itself the assertion that none of ONE,
        // TWO, or FOUR's resolved values are observable on this error path.
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
        };

        let resolved = resolve_profile(&profile, &opts).await.unwrap();
        assert_eq!(resolved.get("TOKEN").unwrap(), "the-secret-value");
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
        };

        let err = resolve_profile(&profile, &opts).await.unwrap_err();
        assert_matches!(err, VaultError::Other(message) if message.contains("release-signer"));
    }
}
