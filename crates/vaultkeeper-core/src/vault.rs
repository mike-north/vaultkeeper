//! VaultKeeper main struct — wires together all vaultkeeper subsystems.

use zeroize::Zeroizing;

use crate::backend::{
    ApprovalContext, HostPlatform, PresenceOperation, SecretBackend, SigningBackend,
    get_backend_capabilities,
};
use crate::config;
use crate::errors::{ExecutableTrustRequiredReason, VaultError};
use crate::identity::handles::{HandleId, HandleTable};
use crate::jwe::{
    CreateTokenOptions, block_token, create_token, decrypt_token, extract_kid, validate_claims,
};
use crate::keys::KeyManager;
use crate::types::{
    ClaimsKind, KeyStatus, LeasePresence, PreflightResult, SigningClaims, TrustTier, VaultClaims,
    VaultConfig, VaultResponse,
};

/// A qualifying description of backends that can satisfy a presence-per-use
/// requirement. Surfaced in [`VaultError::NotCapable`] messages so a caller
/// whose configured backend cannot provide the guarantee is pointed at ones
/// that can. Deliberately describes qualifying *configurations* (not a fixed
/// type list), since the capability is per configured instance — a custom
/// backend may also qualify. Mirrors the TypeScript library's
/// `PRESENCE_PER_USE_QUALIFYING_BACKENDS` (`packages/vaultkeeper/src/vault.ts`).
const PRESENCE_PER_USE_QUALIFYING_BACKENDS: &str = "A qualifying backend forces a distinct, fresh human action per operation — \
     e.g. a YubiKey slot with a touch-per-operation policy or a gpg smartcard with \
     touch-to-sign (both cover every operation), or 1Password in per-access mode \
     (which enforces presence for reads only today, not writes). Switch to (or \
     reconfigure) such a backend, or drop the presence requirement.";

/// Shared enforcement for a presence-per-use requirement.
///
/// Mirrors the TypeScript library's `VaultKeeper.#enforcePresenceRequirement`
/// (`packages/vaultkeeper/src/vault.ts`) exactly. This is meant to be the
/// single, non-bypassable point of enforcement for every backend-touching
/// core operation — not duplicated per caller.
///
/// **Seam note (issue #242 AC3):** `vaultkeeper-core`'s [`VaultKeeper`] does
/// not yet have backend-touching `store`/`retrieve`/`delete`/`sign` methods —
/// today the native CLI calls a [`SecretBackend`] directly (pre-dating the
/// single-core consolidation, see issue #234 Phases 2–3), and the signing
/// path is landing concurrently in issue #237. This function is the ported,
/// fully-tested enforcement primitive those future call sites must invoke
/// before touching their backend, exactly as `store`/`delete`/`setup`/`sign`
/// do in the TS reference; wiring it into new core methods is left to the PRs
/// that add them so this issue does not block on or duplicate that work.
///
/// When `require` is not `Some(true)` this is a no-op. Otherwise it queries
/// the backend's capabilities **fresh on every call** (never cached across
/// operations, so a prior satisfied call can never satisfy a later one — see
/// [`get_backend_capabilities`]) and returns [`VaultError::NotCapable`] —
/// before the caller performs any credential/session/device operation — when
/// the configured instance does not advertise
/// [`crate::backend::BackendCapabilities::presence_per_use`], **or**
/// advertises it but does not force a fresh action for **this** `operation`
/// (see [`crate::backend::BackendCapabilities::presence_enforced_operations`]).
/// This makes enforcement operation-aware and fail-closed: e.g. 1Password
/// `per-access` forces presence for reads but not `store`/`delete`, so a
/// flagged write is refused here rather than silently passing through the
/// cached session client.
///
/// A capability report that itself errors (e.g. a live device probe that
/// fails) also fails closed: the error propagates from here rather than being
/// treated as either capable or non-capable.
///
/// When the backend *is* capable for this operation, this returns `Ok(())`
/// and the caller proceeds to the backend's ordinary operation, which by the
/// meaning of the capability forces a distinct fresh human action for this
/// specific call. The presence action itself (and any
/// [`VaultError::PresenceDeclined`]/[`VaultError::PresenceTimeout`]) therefore
/// surfaces from that backend operation, not from here — so two consecutive
/// required-presence operations each drive their own backend call and each
/// demand their own fresh action.
pub async fn enforce_presence_requirement(
    backend: &dyn SecretBackend,
    operation: PresenceOperation,
    require: Option<bool>,
) -> Result<(), VaultError> {
    if require != Some(true) {
        return Ok(());
    }
    let capabilities = get_backend_capabilities(backend).await?;
    if !capabilities.presence_per_use {
        return Err(VaultError::NotCapable {
            message: format!(
                "This operation required presence-per-use, but the active backend \
                 ('{}') cannot guarantee it. {PRESENCE_PER_USE_QUALIFYING_BACKENDS}",
                backend.backend_type(),
            ),
            backend_type: backend.backend_type().to_string(),
            capability: "presencePerUse".to_string(),
        });
    }
    // Operation-aware, fail-closed: a capable instance that only forces presence
    // for some operations (an explicit `presence_enforced_operations` list) must
    // refuse a flagged operation it does not cover, rather than passing without a
    // fresh action. A `None` list means "all keyed operations" (a touch device).
    if !capabilities.enforces(operation) {
        let enforced_list = capabilities
            .presence_enforced_operations
            .as_ref()
            .map(|ops| {
                ops.iter()
                    .map(|op| op.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default();
        return Err(VaultError::NotCapable {
            message: format!(
                "This '{operation}' operation required presence-per-use, but the active backend \
                 ('{}') only enforces a fresh per-use action for [{enforced_list}] — not \
                 '{operation}'. {PRESENCE_PER_USE_QUALIFYING_BACKENDS}",
                backend.backend_type(),
            ),
            backend_type: backend.backend_type().to_string(),
            capability: "presencePerUse".to_string(),
        });
    }
    Ok(())
}

/// Options for initializing VaultKeeper.
#[derive(Debug, Default)]
pub struct VaultKeeperOptions {
    /// Supply config directly, skipping file load.
    pub config: Option<VaultConfig>,
    /// Skip the doctor preflight check.
    pub skip_doctor: bool,
}

/// Options for the setup operation.
///
/// `setup()` requires an explicit executable-trust decision: supply exactly one
/// of [`SetupOptions::executable_path`] (bind the token to the calling
/// executable) or [`SetupOptions::skip_trust`] (a development-only opt-out).
/// Supplying neither, both, or the retired `"dev"` sentinel as
/// `executable_path` fails with [`VaultError::ExecutableTrustRequired`].
#[derive(Debug, Default)]
pub struct SetupOptions {
    /// TTL in minutes for the JWE.
    pub ttl_minutes: Option<u32>,
    /// Usage limit (`None` for unlimited).
    pub use_limit: Option<u64>,
    /// Executable path to bind the token to (the calling executable's real
    /// path). Mutually exclusive with [`SetupOptions::skip_trust`]. The retired
    /// `"dev"` sentinel is rejected — use `skip_trust: Some(true)` instead.
    pub executable_path: Option<String>,
    /// Development-only opt-out that deliberately skips executable-trust binding,
    /// producing a `"dev"`-bound (unverified) token. Mutually exclusive with
    /// [`SetupOptions::executable_path`].
    pub skip_trust: Option<bool>,
    /// Trust tier override.
    pub trust_tier: Option<crate::types::TrustTier>,
    /// Backend type to use.
    pub backend_type: Option<String>,
}

/// Options for [`VaultKeeper::mint_signing_lease`] (issue #299).
///
/// The caller (the native CLI's `session mint` command, resolving a
/// `signingKey` + `materialize: "lease"` profile entry — see
/// `crate::profile`) has already resolved every field from the profile entry
/// and its defaults; this function performs no profile lookup itself.
#[derive(Debug, Clone, Copy)]
pub struct MintLeaseOptions<'a> {
    /// The profile this mint request came from — surfaced only in the
    /// non-interactive fail-closed error message (issue #299's documented
    /// wording), never used to look anything up.
    pub profile_name: &'a str,
    /// The profile entry (env var) name — same surfacing-only role as
    /// [`MintLeaseOptions::profile_name`].
    pub entry_name: &'a str,
    /// The signing key's name (matches [`VaultClaims::sub`] and the
    /// revocation store's `key_generations` axis — see
    /// [`crate::keys::RevocationState`]).
    pub key_name: &'a str,
    /// Requested TTL in seconds. Capped to
    /// [`crate::profile::SIGNING_LEASE_MAX_TTL_SECONDS`] defensively — the
    /// profile loader already rejects an over-cap `ttlSeconds` before this
    /// function ever runs, but this is not the only caller this function is
    /// designed to have, so the cap is re-enforced here rather than trusted
    /// from the caller.
    pub ttl_seconds: u64,
    /// Trust tier to bind into the lease's `tid` claim.
    pub trust_tier: TrustTier,
    /// Usage limit (`None` for unlimited).
    pub use_limit: Option<u64>,
    /// Whether the entry's `requirePresenceAtMint` policy applies to this
    /// mint.
    pub require_presence_at_mint: bool,
    /// Whether the invocation environment can support an interactive
    /// host-approval fallback when the backend itself cannot force a fresh
    /// touch for `sign` (native CLI: `stderr` is a terminal). `false` means
    /// [`HostPlatform::prompt_approval`] is never called at all — see
    /// [`VaultKeeper::mint_signing_lease`]'s non-interactive fail-closed rule.
    pub interactive: bool,
}

/// Namespace a signing key's caller-facing name into the backend id used to
/// invoke [`SigningBackend`] methods — mirrors the TypeScript library's
/// private `VaultKeeper.#signingKeyId` (`packages/vaultkeeper/src/vault.ts`)
/// so a signing key and an ordinary secret can share the same caller-facing
/// name with no collision risk.
fn signing_key_id(name: &str) -> String {
    format!("signing-key:{name}")
}

/// The non-interactive fail-closed error message (issue #299's documented
/// wording — reproduced verbatim, not paraphrased, since it is part of the
/// design). `profile_lint_hint` is the profile name to embed in the
/// suggested `vaultkeeper profile lint <NAME>` recovery command.
fn non_interactive_presence_error_message(profile_name: &str, entry_name: &str) -> String {
    format!(
        "profile '{profile_name}' entry '{entry_name}' requires human presence at mint,\n\
         but this invocation is non-interactive — stderr is not a terminal and this host\n\
         offers no approval mechanism. A presence-requiring entry cannot be resolved during\n\
         an unattended restart.\n\
         \n\
         Resolve by one of:\n\
         \u{20}\u{20}- Remove requirePresenceAtMint from the entry; it will then resolve unattended.\n\
         \u{20}\u{20}- Do not use this profile as an MCP server `command` — run\n\
         \u{20}\u{20}\u{20}\u{20}'vaultkeeper profile lint {profile_name}' for the full report."
    )
}

/// Main entry point for vaultkeeper. Orchestrates backends, keys, JWE tokens,
/// identity verification, and access patterns.
pub struct VaultKeeper {
    config: VaultConfig,
    key_manager: KeyManager,
    _backend: Option<Box<dyn SecretBackend>>,
    /// Opaque capability-handle table (issue #241): the single accounting
    /// authority for per-JTI usage counts and per-handle expiry/eviction. See
    /// `crate::identity::handles` for the full design.
    handle_table: HandleTable,
    /// Whether key state is persisted to the host's config directory.
    ///
    /// `false` when `VaultKeeperOptions::config` was supplied directly: the
    /// caller is assembling the vault in-process (tests, embedders), so keys
    /// stay in memory only and never touch the config dir — mirroring the TS
    /// `VaultKeeper.init`'s `persistKeys` flag.
    persist_keys: bool,
    /// The highest lease-revocation-store `revStateGen` this instance has
    /// itself observed (issue #298). The anti-rollback anchor for
    /// [`VaultKeeper::validate_lease_revocation`]: `0` on a fresh instance
    /// (any persisted generation satisfies it), and only ever increases —
    /// see [`crate::keys::storage::load_revocation_for_validation`].
    revocation_high_water_mark: u64,
}

impl VaultKeeper {
    /// Initialize a new VaultKeeper instance.
    ///
    /// Runs doctor checks (unless skipped), loads config, and sets up the key manager.
    pub async fn init(
        host: &dyn HostPlatform,
        options: Option<VaultKeeperOptions>,
    ) -> Result<Self, VaultError> {
        let opts = options.unwrap_or_default();
        // Persist key material to disk only when operating against a real
        // on-disk config directory. When `config` is injected, the caller is
        // assembling the vault in-process (tests, embedders), so keys stay in
        // memory and never touch the config dir.
        let persist_keys = opts.config.is_none();

        let cfg = match opts.config {
            Some(c) => c,
            None => config::load_config(host).await?,
        };

        if !opts.skip_doctor {
            let doctor_result = crate::doctor::run_doctor(host, Some(&cfg.backends)).await;
            if !doctor_result.ready {
                return Err(VaultError::Other(format!(
                    "System not ready: {}",
                    doctor_result.next_steps.join("; ")
                )));
            }
        }

        let mut key_manager = KeyManager::new();
        if persist_keys {
            match crate::keys::load_key_state(host).await? {
                Some(snapshot) => key_manager.hydrate(snapshot),
                None => {
                    key_manager.init()?;
                    let snapshot = key_manager.snapshot()?;
                    crate::keys::save_key_state(host, &snapshot).await?;
                }
            }
        } else {
            key_manager.init()?;
        }

        Ok(Self {
            config: cfg,
            key_manager,
            _backend: None,
            handle_table: HandleTable::new(),
            persist_keys,
            revocation_high_water_mark: 0,
        })
    }

    /// Run doctor checks without full initialization.
    ///
    /// Uses conservative platform defaults — all platform-native dependency
    /// checks are treated as required regardless of any backend configuration.
    /// For config-aware scoping, call `run_doctor` with `Some(backends)`.
    pub async fn doctor(host: &dyn HostPlatform) -> PreflightResult {
        crate::doctor::run_doctor(host, None).await
    }

    /// Get a reference to the current config.
    pub fn config(&self) -> &VaultConfig {
        &self.config
    }

    /// Get a reference to the key manager.
    pub fn key_manager(&self) -> &KeyManager {
        &self.key_manager
    }

    /// Get a mutable reference to the key manager.
    pub fn key_manager_mut(&mut self) -> &mut KeyManager {
        &mut self.key_manager
    }

    /// Rotate the current encryption key, then persist the new state so a
    /// later process picks up the rotation (see `keys::storage`).
    pub async fn rotate_key(&mut self, host: &dyn HostPlatform) -> Result<(), VaultError> {
        let grace_period_ms =
            u64::from(self.config.key_rotation.grace_period_days) * 24 * 60 * 60 * 1000;
        self.key_manager.rotate_key(grace_period_ms)?;
        self.persist_key_state(host).await
    }

    /// Emergency key revocation, then persist the new state so a later
    /// process picks up the revocation (see `keys::storage`).
    pub async fn revoke_key(&mut self, host: &dyn HostPlatform) -> Result<(), VaultError> {
        self.key_manager.revoke_key()?;
        self.persist_key_state(host).await
    }

    /// Persist the current key state to the config dir when persistence is
    /// enabled. A no-op for injected-config instances (in-memory keys).
    async fn persist_key_state(&mut self, host: &dyn HostPlatform) -> Result<(), VaultError> {
        if !self.persist_keys {
            return Ok(());
        }
        let snapshot = self.key_manager.snapshot()?;
        crate::keys::save_key_state(host, &snapshot).await
    }

    // --- Lease revocation store (issue #298) -------------------------------

    /// `session revoke --jti <JTI>` — revoke a single outstanding lease.
    /// Read-modify-write (see [`crate::keys::mutate_revocation_state`]): a
    /// `rotateKey`/`revokeKey` call *sequenced* before or after this one (not
    /// genuinely overlapping — see that function's concurrency-scope note)
    /// loses neither writer's own portion of `keys.enc`. Also sweeps every
    /// `jti` entry already past its own `exp` before persisting (AC4) —
    /// bounded growth by construction. `exp` is the revoked token's own
    /// expiry, so the entry can never outlive the token it revokes.
    pub async fn revoke_lease_jti(
        &mut self,
        host: &dyn HostPlatform,
        jti: &str,
        exp: u64,
    ) -> Result<(), VaultError> {
        let jti = jti.to_string();
        let now = crate::util::time::now_secs();
        crate::keys::mutate_revocation_state(host, move |state| {
            state.revoke_jti(jti, exp);
            state.sweep_expired(now);
        })
        .await?;
        Ok(())
    }

    /// `session revoke --key <NAME>` — revoke every outstanding lease for a
    /// named signing key (matches [`VaultClaims::sub`]) in one operation, by
    /// incrementing its generation. See [`VaultKeeper::revoke_lease_jti`] for
    /// the read-modify-write/concurrency contract.
    pub async fn revoke_lease_key(
        &mut self,
        host: &dyn HostPlatform,
        key_name: &str,
    ) -> Result<(), VaultError> {
        let key_name = key_name.to_string();
        crate::keys::mutate_revocation_state(host, move |state| {
            state.revoke_key(key_name);
        })
        .await?;
        Ok(())
    }

    /// Validate a signing-key lease's revocation status against the
    /// persisted revocation store (issue #298).
    ///
    /// Distinct from [`VaultKeeper::authorize`] by design: only the
    /// signing-key-lease (`kty: SigningKey`) path calls this. Ordinary secret
    /// authorization (`authorize`/rung-2 resolution) is entirely unaffected
    /// by revocation-store health — a corrupted or missing revocation store
    /// must not brick secret resolution (AC8).
    ///
    /// `claims` is expected to have already passed
    /// [`crate::jwe::validate_claims`] (so `jti`/`sub` are non-empty and
    /// `kty`/`kgen` obey the signing-lease shape) — this function re-checks
    /// `kty`/`kgen` defensively rather than trusting the caller, but does not
    /// repeat expiry/usage-limit/shape validation.
    ///
    /// Tracks the highest `revStateGen` this instance has itself observed
    /// (`self.revocation_high_water_mark`) as the anti-rollback anchor: see
    /// [`crate::keys::storage::load_revocation_for_validation`].
    ///
    /// # Errors
    /// Returns [`VaultError::TokenRevoked`] if `claims` carries no `kgen`
    /// (fail closed — never defaulted to generation 0), the revocation store
    /// cannot be trusted (missing, tampered, or rolled back), the `jti` is on
    /// the revoked list, or `kgen` is below the current minimum for `sub`.
    /// Environmental failures reading the store (e.g. a permissions error on
    /// an existing `keys.enc`) propagate as their own typed variants (such as
    /// [`VaultError::Filesystem`]) rather than being disguised as revocation —
    /// every error path refuses validation, so callers must treat *any* `Err`
    /// as fail-closed, not only `TokenRevoked`.
    /// Returns [`VaultError::Other`] if `claims.kty` is not `SigningKey`.
    pub async fn validate_lease_revocation(
        &mut self,
        host: &dyn HostPlatform,
        claims: &VaultClaims,
    ) -> Result<(), VaultError> {
        if claims.kty != Some(ClaimsKind::SigningKey) {
            return Err(VaultError::Other(
                "validate_lease_revocation() called on claims that are not a signing-key lease"
                    .to_string(),
            ));
        }
        // Fail closed: an unversioned lease is rejected outright, never
        // treated as generation 0 — see `crate::jwe::validate_claims`, which
        // already enforces this on the mint/authorize path. Re-checked here
        // defensively since this function does not assume its caller ran
        // that validation first.
        let Some(kgen) = claims.kgen else {
            return Err(VaultError::TokenRevoked {
                message: format!(
                    "Lease {} refused: claims carry no kgen (unversioned lease)",
                    claims.jti
                ),
            });
        };

        let state =
            crate::keys::load_revocation_for_validation(host, self.revocation_high_water_mark)
                .await?;
        self.revocation_high_water_mark = self.revocation_high_water_mark.max(state.rev_state_gen);

        if state.is_jti_revoked(&claims.jti) {
            return Err(VaultError::TokenRevoked {
                message: format!("Lease {} has been revoked (jti)", claims.jti),
            });
        }

        let min_gen = state.min_generation_for(&claims.sub);
        if kgen < min_gen {
            return Err(VaultError::TokenRevoked {
                message: format!(
                    "Lease {} for key '{}' has been revoked: kgen {kgen} is below the current \
                     minimum generation {min_gen}",
                    claims.jti, claims.sub
                ),
            });
        }

        Ok(())
    }

    /// Store a secret value and produce a JWE token encapsulating it.
    ///
    /// The returned compact JWE string can be passed to `authorize()` or
    /// the CLI `exec` command to retrieve the secret.
    ///
    /// The caller must make an explicit executable-trust decision via
    /// [`SetupOptions`]: supply exactly one of
    /// [`SetupOptions::executable_path`] (verify and bind the calling
    /// executable) or [`SetupOptions::skip_trust`] (a development-only opt-out).
    /// Supplying neither, both, or the retired `"dev"` sentinel as
    /// `executable_path` returns [`VaultError::ExecutableTrustRequired`] rather
    /// than silently minting an unverified `"dev"`-bound token.
    ///
    /// When an `executable_path` is supplied, the executable is hashed and run
    /// through trust verification ([`crate::identity::trust`]): Sigstore →
    /// trust-manifest match → TOFU first-encounter. A hash that conflicts with a
    /// previously approved value returns [`VaultError::IdentityMismatch`]. The
    /// verified hash is bound into the token's `exe` claim.
    ///
    /// **Ordering (issue #148):** shape validation fails fast before any side
    /// effect, and a first-encounter TOFU manifest write is committed only after
    /// the token has successfully minted — so a failed `setup()` never leaves a
    /// premature trust record behind.
    pub async fn setup(
        &self,
        host: &dyn HostPlatform,
        secret_name: &str,
        secret_value: &str,
        options: Option<&SetupOptions>,
    ) -> Result<String, VaultError> {
        let ttl_minutes = options
            .and_then(|o| o.ttl_minutes)
            .unwrap_or(self.config.defaults.ttl_minutes);
        let use_limit = options.and_then(|o| o.use_limit);
        // Verify phase: validates the trust choice and computes the identity to
        // bind, but defers any manifest write to `pending_trust.commit()` below.
        let (exe, pending_trust) = Self::resolve_executable_identity(host, options).await?;
        let trust_tier = options
            .and_then(|o| o.trust_tier)
            .unwrap_or(self.config.defaults.trust_tier);
        let backend_type = options
            .and_then(|o| o.backend_type.as_deref())
            .unwrap_or("file")
            .to_string();

        let now = crate::util::time::now_secs();

        let claims = VaultClaims {
            jti: uuid::Uuid::new_v4().to_string(),
            exp: now + u64::from(ttl_minutes) * 60,
            iat: now,
            sub: secret_name.to_string(),
            exe,
            use_limit,
            tid: trust_tier,
            bkd: Some(backend_type),
            val: Some(secret_value.to_string()),
            reference: secret_name.to_string(),
            kty: None,
            kid: None,
            kgen: None,
            pres: None,
        };

        let current_key = self.key_manager.get_current_key()?;
        let token = create_token(
            &current_key.key,
            &claims,
            &CreateTokenOptions {
                kid: Some(current_key.id.clone()),
            },
        )?;

        // Commit the deferred TOFU manifest write only now that the token has
        // minted successfully. A failure anywhere above leaves the manifest
        // untouched (issue #148). A no-op when there is nothing to record
        // (skip_trust, a manifest/Sigstore match, or a conflict).
        if let Some(pending) = pending_trust {
            pending.commit(host).await?;
        }

        Ok(token)
    }

    /// Resolve the executable identity to bind into a token, requiring an
    /// explicit trust decision from the caller.
    ///
    /// Returns the sentinel `"dev"` (no executable binding, nothing to commit)
    /// when trust is deliberately skipped; otherwise hashes the supplied
    /// executable and runs it through trust verification
    /// ([`crate::identity::trust::verify_trust_pending`]) — Sigstore →
    /// trust-manifest match → TOFU first-encounter — returning the verified hash
    /// to bind into the token's `exe` claim, together with any deferred manifest
    /// write for the caller to commit after the token mints (issue #148).
    ///
    /// Returns [`VaultError::ExecutableTrustRequired`] when the caller makes no
    /// unambiguous choice — mirroring the TypeScript library's
    /// `ExecutableTrustRequiredError` (message + `reason` discriminator) — or
    /// [`VaultError::IdentityMismatch`] when the executable's current hash
    /// conflicts with a previously approved value (TOFU conflict).
    async fn resolve_executable_identity(
        host: &dyn HostPlatform,
        options: Option<&SetupOptions>,
    ) -> Result<(String, Option<crate::identity::trust::PendingTrust>), VaultError> {
        let executable_path = options.and_then(|o| o.executable_path.as_deref());
        let skip_trust = options.and_then(|o| o.skip_trust).unwrap_or(false);

        if skip_trust && executable_path.is_some() {
            return Err(VaultError::ExecutableTrustRequired {
                message: "VaultKeeper::setup() received both SetupOptions.executable_path and \
                          SetupOptions.skip_trust: Some(true), which are mutually exclusive. Set \
                          SetupOptions.executable_path to bind the calling executable's identity, \
                          or SetupOptions.skip_trust: Some(true) to skip the binding (development \
                          only) — not both."
                    .to_string(),
                reason: ExecutableTrustRequiredReason::ConflictingChoice,
            });
        }

        if skip_trust {
            // Explicit, greppable development-only opt-out: no executable identity
            // is bound and nothing is recorded.
            return Ok(("dev".to_string(), None));
        }

        let path = match executable_path {
            None => {
                return Err(VaultError::ExecutableTrustRequired {
                    message:
                        "VaultKeeper::setup() requires an explicit executable-trust choice and \
                              no longer defaults to skipping it. Either set \
                              SetupOptions.executable_path to the calling executable's real path \
                              (verifies and binds that identity into the token), or set \
                              SetupOptions.skip_trust: Some(true) to deliberately skip the binding \
                              (development only)."
                            .to_string(),
                    reason: ExecutableTrustRequiredReason::MissingChoice,
                });
            }
            // Reject the retired legacy opt-out sentinel. Before explicit-trust,
            // executable_path: "dev" was the documented way to skip the identity
            // binding; point migrating callers at the dedicated opt-out.
            Some("dev") => {
                return Err(VaultError::ExecutableTrustRequired {
                    message: "VaultKeeper::setup() no longer supports the legacy SetupOptions.executable_path: \
                              \"dev\" sentinel for skipping the identity binding. Set SetupOptions.skip_trust: \
                              Some(true) to deliberately skip the binding (development only), or set \
                              SetupOptions.executable_path to the calling executable's real path to bind it."
                        .to_string(),
                    reason: ExecutableTrustRequiredReason::LegacyDevSentinel,
                });
            }
            // An empty or whitespace-only executable path is not a real trust
            // choice: it would mint a token whose `exe` claim fails the
            // not-empty invariant in validate_claims(), so authorize() would
            // later reject it as an unusable token. Reject it up front as a
            // missing choice rather than hashing and minting the bad token.
            Some(path) if path.trim().is_empty() => {
                return Err(VaultError::ExecutableTrustRequired {
                    message: "VaultKeeper::setup() received an empty SetupOptions.executable_path, which \
                              is not a valid executable-trust choice. Set SetupOptions.executable_path to \
                              the calling executable's real path (verifies and binds that identity into the \
                              token), or set SetupOptions.skip_trust: Some(true) to deliberately skip the \
                              binding (development only)."
                        .to_string(),
                    reason: ExecutableTrustRequiredReason::MissingChoice,
                });
            }
            Some(path) => path,
        };

        // Verify phase (no side effect yet): hash + manifest consultation.
        let pending = crate::identity::trust::verify_trust_pending(host, path, None).await?;

        if pending.tofu_conflict {
            // Mirror the TypeScript library's `#resolveExecutableIdentity`: on a
            // conflict report the most-recently approved hash as the previous one.
            let previous_hash = pending
                .approved_hashes
                .last()
                .cloned()
                .unwrap_or_else(|| pending.identity.hash.clone());
            return Err(VaultError::IdentityMismatch {
                message: "Executable hash changed — re-approval required".to_string(),
                previous_hash,
                current_hash: pending.identity.hash.clone(),
            });
        }

        Ok((pending.identity.hash.clone(), Some(pending)))
    }

    /// Mint a session signing-key lease (issue #299): a serializable,
    /// expiring, revocable, presence-minted authorization to use a signing
    /// key. Same JWE envelope as [`VaultKeeper::setup`] — encrypted under the
    /// vault key via [`KeyManager`], so rotation and `revokeKey()` already
    /// apply — but a distinct claims payload with no `val` (see
    /// [`VaultClaims`]'s kty-discriminated shape).
    ///
    /// **Presence-at-mint** (`options.require_presence_at_mint`): proven via
    /// exactly one of two mechanisms, never both, never neither with a
    /// fabricated `pres`:
    /// - `"backend-touch"` — [`enforce_presence_requirement`] with
    ///   [`PresenceOperation::Sign`] succeeds (the backend advertises
    ///   [`crate::backend::BackendCapabilities::enforces`] for `Sign`).
    /// - `"host-approval"` — [`HostPlatform::prompt_approval`] returns
    ///   `Ok(true)`, tried only when `options.interactive` is `true` and only
    ///   after backend-touch has already failed.
    ///
    /// When `options.interactive` is `false` and backend-touch is
    /// unavailable, `prompt_approval` is never called at all — this is the
    /// non-interactive fail-closed rule (issue #299): a restart with no human
    /// present must refuse promptly (bounded, never an unbounded hang, never
    /// a cached/reuse-window fallback) rather than block on an approval
    /// channel that cannot be satisfied. When neither mechanism is available,
    /// this returns [`VaultError::NotCapable`] — never a lease with an
    /// empty/fabricated `pres`.
    ///
    /// `kgen` is stamped from the signing key's *current* generation, read
    /// fresh from the persisted revocation store (issue #298) via
    /// [`crate::keys::load_revocation_for_validation`] — never cached, never
    /// defaulted — so a lease minted after a `session revoke --key` bump
    /// carries the post-revocation generation, and a corrupt/missing
    /// revocation store fails the mint closed rather than stamping a
    /// fabricated `kgen`.
    ///
    /// # Errors
    /// Returns [`VaultError::SigningKeyNotFound`] if `options.key_name` has no
    /// enrolled signing key. Returns [`VaultError::NotCapable`] if presence is
    /// required but unprovable (see above). Returns [`VaultError::TokenRevoked`]
    /// if the persisted revocation store cannot be read (see
    /// [`crate::keys::load_revocation_for_validation`]'s fail-closed
    /// contract).
    pub async fn mint_signing_lease(
        &self,
        host: &dyn HostPlatform,
        backend: &dyn SigningBackend,
        options: &MintLeaseOptions<'_>,
    ) -> Result<String, VaultError> {
        let backend_ref = signing_key_id(options.key_name);
        let public_key = backend.get_public_key(&backend_ref).await?;

        let pres = if options.require_presence_at_mint {
            Some(Self::prove_presence_at_mint(host, backend, options).await?)
        } else {
            None
        };

        // Fresh on every mint (issue #298): never cached, so a revocation
        // recorded after the last mint is always reflected here.
        let revocation = crate::keys::load_revocation_for_validation(host, 0).await?;
        let kgen = revocation.min_generation_for(options.key_name);

        let now = crate::util::time::now_secs();
        let ttl_seconds = options
            .ttl_seconds
            .min(crate::profile::SIGNING_LEASE_MAX_TTL_SECONDS);

        let claims = VaultClaims {
            jti: uuid::Uuid::new_v4().to_string(),
            exp: now + ttl_seconds,
            iat: now,
            sub: options.key_name.to_string(),
            exe: "dev".to_string(),
            use_limit: options.use_limit,
            tid: options.trust_tier,
            bkd: None,
            val: None,
            reference: backend_ref,
            kty: Some(ClaimsKind::SigningKey),
            kid: Some(public_key.kid),
            kgen: Some(kgen),
            pres,
        };

        let current_key = self.key_manager.get_current_key()?;
        create_token(
            &current_key.key,
            &claims,
            &CreateTokenOptions {
                kid: Some(current_key.id.clone()),
            },
        )
    }

    /// Prove presence for a [`VaultKeeper::mint_signing_lease`] call — see
    /// that method's doc comment for the two mechanisms and the
    /// non-interactive fail-closed rule.
    async fn prove_presence_at_mint(
        host: &dyn HostPlatform,
        backend: &dyn SecretBackend,
        options: &MintLeaseOptions<'_>,
    ) -> Result<LeasePresence, VaultError> {
        let now = crate::util::time::now_secs();

        match enforce_presence_requirement(backend, PresenceOperation::Sign, Some(true)).await {
            Ok(()) => Ok(LeasePresence {
                op: "sign".to_string(),
                at: now,
                method: "backend-touch".to_string(),
                backend: backend.backend_type().to_string(),
            }),
            Err(backend_touch_err) => {
                if !options.interactive {
                    // Never call prompt_approval at all here — the guard that
                    // guarantees this path can never hang waiting on an
                    // approval channel with no human behind it.
                    return Err(VaultError::NotCapable {
                        message: non_interactive_presence_error_message(
                            options.profile_name,
                            options.entry_name,
                        ),
                        backend_type: backend.backend_type().to_string(),
                        capability: "presenceAtMint".to_string(),
                    });
                }

                match host
                    .prompt_approval(ApprovalContext {
                        action: "session-mint",
                        detail: options.entry_name,
                    })
                    .await
                {
                    Ok(true) => Ok(LeasePresence {
                        op: "sign".to_string(),
                        at: now,
                        method: "host-approval".to_string(),
                        backend: backend.backend_type().to_string(),
                    }),
                    Ok(false) => Err(backend_touch_err),
                    Err(e) => Err(e),
                }
            }
        }
    }

    /// Decrypt a JWE token, validate its claims, and return an opaque
    /// capability [`HandleId`] together with the (secret-redacted) claims and
    /// key status. Tracks per-JTI usage counts and blocks tokens that exceed
    /// their use limit.
    ///
    /// **The returned [`VaultClaims::val`] is always empty (issue #241 AC1)**
    /// — the raw secret never leaves core memory through this return value.
    /// It stays behind the returned handle, in a [`Zeroizing`] buffer, until
    /// [`VaultKeeper::read_secret`] consumes it exactly once. The handle's
    /// lifetime is bound to the token's own `exp`/`use_limit` claims, not to
    /// any interactive session — see `crate::identity::handles` for the full
    /// eviction-policy rationale.
    pub fn authorize(
        &mut self,
        jwe: &str,
    ) -> Result<(HandleId, VaultClaims, VaultResponse), VaultError> {
        let kid = extract_kid(jwe)?;

        let (key, is_current) = match &kid {
            Some(k) => {
                self.key_manager
                    .find_key_by_id(k)
                    .ok_or_else(|| VaultError::KeyRevoked {
                        message: format!("Unknown key ID: {k}"),
                    })?
            }
            None => {
                let k = self.key_manager.get_current_key()?;
                (k, true)
            }
        };

        let claims = decrypt_token(&key.key, jwe)?;

        let current_usage = self.handle_table.current_usage(&claims.jti);
        validate_claims(&claims, current_usage)?;

        // Increment usage count
        let new_usage = self.handle_table.record_usage(&claims.jti);

        // If usage limit reached, block the token for future requests
        if let Some(limit) = claims.use_limit
            && new_usage >= limit
        {
            block_token(&claims.jti);
        }

        let key_status = if is_current {
            KeyStatus::Current
        } else {
            KeyStatus::Previous
        };

        let mut response = VaultResponse {
            key_status,
            rotated_jwt: None,
        };

        // If decrypted with previous key, re-encrypt with current
        if !is_current {
            let current_key = self.key_manager.get_current_key()?;
            let rotated = create_token(
                &current_key.key,
                &claims,
                &CreateTokenOptions {
                    kid: Some(current_key.id.clone()),
                },
            )?;
            response.rotated_jwt = Some(rotated);
        }

        // The handle's expiry is bound to the token's own `exp` — a
        // long-lived, non-interactively-refreshed token (see the "Why
        // `expires_at` must stay caller-supplied" note in
        // `crate::identity::handles`) produces a correspondingly long-lived
        // handle, with no additional core-imposed shorter lifetime.
        let expires_at = Some(claims.exp);
        // Build the redacted claims to return *without* ever cloning `val`:
        // `VaultClaims::clone()` would duplicate the secret into a second,
        // non-zeroizing `String` allocation, and dropping that duplicate
        // (even immediately) leaves the plaintext sitting in freed heap
        // memory — ordinary `String`/`Drop` does not scrub its buffer. Every
        // other field is non-secret, so cloning them individually is fine;
        // `val` is simply never read here, so no unprotected copy of the
        // secret is ever created on this path. The one true copy of the
        // secret moves straight from `claims` into the handle table's
        // `Zeroizing` buffer via `insert_secret` below.
        let public_claims = VaultClaims {
            jti: claims.jti.clone(),
            exp: claims.exp,
            iat: claims.iat,
            sub: claims.sub.clone(),
            exe: claims.exe.clone(),
            use_limit: claims.use_limit,
            tid: claims.tid,
            bkd: claims.bkd.clone(),
            val: None,
            reference: claims.reference.clone(),
            kty: claims.kty,
            kid: claims.kid.clone(),
            kgen: claims.kgen,
            pres: claims.pres.clone(),
        };
        let handle_id = self.handle_table.insert_secret(claims, expires_at);

        Ok((handle_id, public_claims, response))
    }

    /// Read the raw secret behind `handle` exactly once (issue #241 AC2). A
    /// second read, or a call after the handle expired/was released, returns
    /// a typed [`VaultError`] rather than the secret. Refuses a signing-key
    /// handle (AC3).
    pub fn read_secret(&mut self, handle: &HandleId) -> Result<Zeroizing<String>, VaultError> {
        self.handle_table.read_secret(handle)
    }

    /// Resolve non-secret claims behind `handle` for a fetch/exec/`getSecret`
    /// consumer (issue #241 AC2 — no secret egress). Refuses a signing-key
    /// handle (AC3).
    pub fn resolve_secret_claims(&mut self, handle: &HandleId) -> Result<VaultClaims, VaultError> {
        self.handle_table.resolve_secret_claims(handle)
    }

    /// Resolve signing claims behind `handle` for a `sign()` consumer.
    /// Refuses a secret handle (issue #241 AC3).
    pub fn resolve_signing_claims(
        &mut self,
        handle: &HandleId,
    ) -> Result<SigningClaims, VaultError> {
        self.handle_table.resolve_signing_claims(handle)
    }

    /// Explicitly release `handle`, evicting it immediately. Returns `true`
    /// if a handle was actually present and removed. See
    /// `crate::identity::handles` for why this is the preferred eviction
    /// path over waiting on expiry.
    pub fn release_handle(&mut self, handle: &HandleId) -> bool {
        self.handle_table.release(handle)
    }

    /// Proactively evict every handle past its expiry. Returns the number of
    /// handles evicted. Not required for correctness (every resolve/read
    /// path already checks expiry lazily) — exposed for a host that wants to
    /// sweep eagerly (e.g. a CLI daemon loop's periodic tick).
    pub fn sweep_expired_handles(&mut self) -> usize {
        self.handle_table.sweep_expired()
    }

    /// Register a signing-key capability handle directly (issue #241
    /// AC3/AC6 — a low-level primitive for the future engine swap).
    ///
    /// This does not itself mint or validate a token, nor call a
    /// `SigningBackend` — a caller that has already resolved `(kid,
    /// backend_ref)` for an enrolled signing key (e.g. a future Rust port of
    /// the TypeScript `authorizeSigningKey()`) registers it here to obtain a
    /// handle usable with [`VaultKeeper::resolve_signing_claims`]. The
    /// underlying lifetime model stays structurally open to a caller-chosen
    /// `expires_at` — see `crate::identity::handles` — but a never-expiring
    /// (`None`) signing handle is refused with
    /// [`VaultError::AuthorizationDenied`] until an issuance-side principal
    /// check exists — an open product decision tracked in issue #261, with
    /// this gate itself tracked in issue #282: with no invocation-time
    /// re-check anywhere in the system, a `None` expiry would mint a
    /// durable ambient signing capability redeemable by mere possession of
    /// the returned [`HandleId`]. A finite `expires_at` is unaffected and
    /// registers exactly as before.
    ///
    /// Only reachable from within this crate — `register_signing_handle` has
    /// no callers today; the future lease-mint path referenced above is
    /// in-crate.
    // Allowed: no in-crate caller exists yet — the future lease-mint path
    // (issue #282) is the intended first caller. `#[cfg(test)]` exercises
    // this method directly in the meantime.
    #[allow(dead_code)]
    pub(crate) fn register_signing_handle(
        &mut self,
        kid: String,
        backend_ref: String,
        expires_at: Option<u64>,
    ) -> Result<HandleId, VaultError> {
        let Some(expires_at) = expires_at else {
            return Err(VaultError::AuthorizationDenied {
                message: "long-lived signing handles are gated on an issuance-side principal check — see #282".into(),
            });
        };
        Ok(self
            .handle_table
            .insert_signing(SigningClaims { kid, backend_ref }, Some(expires_at)))
    }
}

#[cfg(test)]
mod register_signing_handle_tests {
    use std::collections::HashMap;

    use super::{HandleTable, KeyManager, VaultError, VaultKeeper};
    use crate::types::{BackendConfig, KeyRotationPolicy, TrustTier, VaultConfig, VaultDefaults};

    /// A minimal in-memory `VaultKeeper` — bypasses `init()`'s host/doctor/
    /// disk-persistence machinery (issue #282 regression tests only need the
    /// handle table and a key manager, not a real backend).
    fn test_vault_keeper() -> VaultKeeper {
        let mut key_manager = KeyManager::new();
        key_manager.init().expect("key manager init");
        VaultKeeper {
            config: VaultConfig {
                version: 1,
                backends: vec![BackendConfig {
                    backend_type: "file".to_string(),
                    enabled: true,
                    plugin: None,
                    path: Some("/tmp/vault-282".to_string()),
                    options: Some(HashMap::new()),
                }],
                key_rotation: KeyRotationPolicy {
                    grace_period_days: 7,
                },
                defaults: VaultDefaults {
                    ttl_minutes: 60,
                    trust_tier: TrustTier::Dev,
                },
                development_mode: None,
            },
            key_manager,
            _backend: None,
            handle_table: HandleTable::new(),
            persist_keys: false,
            revocation_high_water_mark: 0,
        }
    }

    /// Regression test for issue #282: a signing handle registered with
    /// `expires_at: None` must be refused — pre-fix code minted it
    /// unconditionally, producing a repeatable, never-expiring signing
    /// capability redeemable by mere possession of the `HandleId`, with no
    /// invocation-time principal check anywhere in the system.
    #[test]
    fn none_expiry_signing_handle_is_gated() {
        let mut vault = test_vault_keeper();

        let result =
            vault.register_signing_handle("kid-1".to_string(), "backend-ref-1".to_string(), None);

        let err = result.expect_err("None expiry must be refused");
        match err {
            VaultError::AuthorizationDenied { message } => {
                assert!(
                    message.contains("282"),
                    "gate error message should name the tracking issue: {message}"
                );
            }
            other => panic!("expected AuthorizationDenied, got {other:?}"),
        }
    }

    /// A finite `expires_at` must keep registering and resolving exactly as
    /// before the #282 gate was added.
    #[test]
    fn finite_expiry_signing_handle_still_registers_and_resolves() {
        let mut vault = test_vault_keeper();

        let handle = vault
            .register_signing_handle(
                "kid-2".to_string(),
                "backend-ref-2".to_string(),
                Some(u64::MAX),
            )
            .expect("finite expiry must register");

        let claims = vault
            .resolve_signing_claims(&handle)
            .expect("registered signing handle must resolve");
        assert_eq!(claims.kid, "kid-2");
        assert_eq!(claims.backend_ref, "backend-ref-2");
    }
}

#[cfg(test)]
mod mint_signing_lease_tests {
    use super::*;
    use crate::backend::{
        BackendCapabilities, ExecOptions, ExecOutput, Platform, PresenceCapableBackend,
    };
    use crate::jwe::decrypt_token;
    use crate::types::SigningAlgorithm;
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // -------------------------------------------------------------------
    // Test doubles
    // -------------------------------------------------------------------

    /// A `HostPlatform` backed by an in-memory file map — real enough to
    /// exercise `VaultKeeper::init`'s key-state persistence (so
    /// `load_revocation_for_validation` has a genuine store to read) without
    /// touching the filesystem. `approve` controls the canned
    /// `prompt_approval` answer; `prompt_calls` counts how many times it was
    /// actually invoked, so the non-interactive fail-closed path can assert
    /// it is *never* called (not merely that it answers `false`).
    struct TestHost {
        files: Mutex<HashMap<PathBuf, Vec<u8>>>,
        config_dir: PathBuf,
        approve: bool,
        prompt_calls: AtomicUsize,
    }

    impl TestHost {
        fn new(approve: bool) -> Self {
            Self {
                files: Mutex::new(HashMap::new()),
                config_dir: PathBuf::from("/test/config"),
                approve,
                prompt_calls: AtomicUsize::new(0),
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
        async fn prompt_approval(&self, _context: ApprovalContext<'_>) -> Result<bool, VaultError> {
            self.prompt_calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.approve)
        }
        async fn read_file(&self, path: &Path) -> Result<Vec<u8>, VaultError> {
            self.files
                .lock()
                .unwrap()
                .get(path)
                .cloned()
                .ok_or_else(|| VaultError::Other(format!("not found: {}", path.display())))
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
                .ok_or_else(|| VaultError::Other(format!("not found: {}", from.display())))?;
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

    /// A `SigningBackend` test double whose presence capabilities are
    /// configurable per test — `get_public_key`/`sign_with_key` are stubs
    /// that never touch real key material.
    struct MockSigningBackend {
        capabilities: BackendCapabilities,
    }

    #[async_trait::async_trait]
    impl SecretBackend for MockSigningBackend {
        fn backend_type(&self) -> &str {
            "mock-signing"
        }
        fn display_name(&self) -> &str {
            "Mock Signing Backend"
        }
        async fn is_available(&self) -> bool {
            true
        }
        async fn store(&self, _id: &str, _secret: &str) -> Result<(), VaultError> {
            Ok(())
        }
        async fn retrieve(&self, _id: &str) -> Result<String, VaultError> {
            Err(VaultError::Other("not supported".to_string()))
        }
        async fn delete(&self, _id: &str) -> Result<(), VaultError> {
            Ok(())
        }
        async fn exists(&self, _id: &str) -> Result<bool, VaultError> {
            Ok(false)
        }
        fn as_presence_capable(&self) -> Option<&dyn PresenceCapableBackend> {
            Some(self)
        }
    }

    #[async_trait::async_trait]
    impl PresenceCapableBackend for MockSigningBackend {
        async fn get_capabilities(&self) -> Result<BackendCapabilities, VaultError> {
            Ok(self.capabilities.clone())
        }
    }

    #[async_trait::async_trait]
    impl SigningBackend for MockSigningBackend {
        async fn generate_signing_key(
            &self,
            _id: &str,
            _algorithm: SigningAlgorithm,
        ) -> Result<(), VaultError> {
            Ok(())
        }
        async fn get_public_key(
            &self,
            id: &str,
        ) -> Result<crate::types::SigningPublicKey, VaultError> {
            Ok(crate::types::SigningPublicKey {
                public_key_pem: "PEM".to_string(),
                algorithm: SigningAlgorithm::EdDsa,
                kid: format!("kid-for-{id}"),
            })
        }
        async fn sign_with_key(&self, _id: &str, _data: &[u8]) -> Result<Vec<u8>, VaultError> {
            Ok(Vec::new())
        }
    }

    async fn init_vault(host: &TestHost) -> VaultKeeper {
        VaultKeeper::init(
            host,
            Some(VaultKeeperOptions {
                config: None,
                skip_doctor: true,
            }),
        )
        .await
        .expect("vault init")
    }

    fn base_options(
        interactive: bool,
        require_presence_at_mint: bool,
    ) -> MintLeaseOptions<'static> {
        MintLeaseOptions {
            profile_name: "github-mcp",
            entry_name: "VK_SIGNING_LEASE",
            key_name: "release-signer",
            ttl_seconds: crate::profile::SIGNING_LEASE_DEFAULT_TTL_SECONDS,
            trust_tier: TrustTier::Dev,
            use_limit: None,
            require_presence_at_mint,
            interactive,
        }
    }

    // --- AC1: no Sign presence -> NotCapable, never a fabricated pres ---

    #[tokio::test]
    async fn backend_with_no_sign_presence_fails_with_not_capable() {
        let host = TestHost::new(false);
        let vault = init_vault(&host).await;
        let backend = MockSigningBackend {
            capabilities: BackendCapabilities::none(),
        };
        let options = base_options(true, true);

        let err = vault
            .mint_signing_lease(&host, &backend, &options)
            .await
            .expect_err("must refuse without a proven presence mechanism");

        assert!(
            matches!(err, VaultError::NotCapable { .. }),
            "expected NotCapable, got {err:?}"
        );
    }

    #[tokio::test]
    async fn backend_that_enforces_only_other_operations_fails_with_not_capable() {
        let host = TestHost::new(false);
        let vault = init_vault(&host).await;
        let backend = MockSigningBackend {
            capabilities: BackendCapabilities {
                presence_per_use: true,
                presence_enforced_operations: Some(vec![PresenceOperation::Read]),
            },
        };
        let options = base_options(true, true);

        let err = vault
            .mint_signing_lease(&host, &backend, &options)
            .await
            .expect_err("Read-only presence coverage must not satisfy Sign");

        assert!(matches!(err, VaultError::NotCapable { .. }));
    }

    // --- AC2: pres.method reflects the mechanism actually used ---

    #[tokio::test]
    async fn pres_method_is_backend_touch_when_the_backend_enforces_sign() {
        let host = TestHost::new(false);
        let vault = init_vault(&host).await;
        let backend = MockSigningBackend {
            capabilities: BackendCapabilities {
                presence_per_use: true,
                presence_enforced_operations: None,
            },
        };
        let options = base_options(true, true);

        let jwe = vault
            .mint_signing_lease(&host, &backend, &options)
            .await
            .expect("capable backend must mint");
        let key = vault.key_manager().get_current_key().unwrap();
        let claims = decrypt_token(&key.key, &jwe).unwrap();

        let pres = claims
            .pres
            .expect("presence-required lease must carry pres");
        assert_eq!(pres.method, "backend-touch");
        assert_eq!(pres.op, "sign");
        assert_eq!(pres.backend, "mock-signing");
        assert_eq!(host.prompt_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn pres_method_is_host_approval_when_the_backend_is_incapable_but_host_approves() {
        let host = TestHost::new(true);
        let vault = init_vault(&host).await;
        let backend = MockSigningBackend {
            capabilities: BackendCapabilities::none(),
        };
        let options = base_options(true, true);

        let jwe = vault
            .mint_signing_lease(&host, &backend, &options)
            .await
            .expect("host approval must satisfy presence");
        let key = vault.key_manager().get_current_key().unwrap();
        let claims = decrypt_token(&key.key, &jwe).unwrap();

        let pres = claims
            .pres
            .expect("presence-required lease must carry pres");
        assert_eq!(pres.method, "host-approval");
        assert_eq!(host.prompt_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn no_presence_required_mints_with_no_pres_and_no_prompt() {
        let host = TestHost::new(false);
        let vault = init_vault(&host).await;
        let backend = MockSigningBackend {
            capabilities: BackendCapabilities::none(),
        };
        let options = base_options(true, false);

        let jwe = vault
            .mint_signing_lease(&host, &backend, &options)
            .await
            .expect("presence-not-required entry must mint unattended");
        let key = vault.key_manager().get_current_key().unwrap();
        let claims = decrypt_token(&key.key, &jwe).unwrap();

        assert!(claims.pres.is_none());
        assert_eq!(host.prompt_calls.load(Ordering::SeqCst), 0);
    }

    // --- Non-interactive fail-closed rule ---

    #[tokio::test]
    async fn non_interactive_invocation_fails_closed_without_ever_calling_prompt_approval() {
        let host = TestHost::new(true); // would approve if ever asked
        let vault = init_vault(&host).await;
        let backend = MockSigningBackend {
            capabilities: BackendCapabilities::none(),
        };
        let options = base_options(false, true);

        let err = vault
            .mint_signing_lease(&host, &backend, &options)
            .await
            .expect_err("non-interactive + presence-required must fail closed");

        match err {
            VaultError::NotCapable { message, .. } => {
                assert!(message.contains("github-mcp"), "{message}");
                assert!(message.contains("VK_SIGNING_LEASE"), "{message}");
                assert!(message.contains("non-interactive"), "{message}");
                assert!(message.contains("unattended restart"), "{message}");
            }
            other => panic!("expected NotCapable, got {other:?}"),
        }
        assert_eq!(
            host.prompt_calls.load(Ordering::SeqCst),
            0,
            "prompt_approval must never be called when non-interactive"
        );
    }

    // --- AC3: exp derived from ttlSeconds (default + hard cap), kgen matches
    // --- the current key generation ---

    #[tokio::test]
    async fn exp_defaults_to_the_eight_hour_ttl() {
        let host = TestHost::new(false);
        let vault = init_vault(&host).await;
        let backend = MockSigningBackend {
            capabilities: BackendCapabilities::none(),
        };
        let options = base_options(true, false);

        let jwe = vault
            .mint_signing_lease(&host, &backend, &options)
            .await
            .unwrap();
        let key = vault.key_manager().get_current_key().unwrap();
        let claims = decrypt_token(&key.key, &jwe).unwrap();

        assert_eq!(
            claims.exp - claims.iat,
            crate::profile::SIGNING_LEASE_DEFAULT_TTL_SECONDS
        );
    }

    #[tokio::test]
    async fn a_requested_ttl_above_the_hard_cap_is_capped_not_rejected() {
        let host = TestHost::new(false);
        let vault = init_vault(&host).await;
        let backend = MockSigningBackend {
            capabilities: BackendCapabilities::none(),
        };
        let mut options = base_options(true, false);
        options.ttl_seconds = crate::profile::SIGNING_LEASE_MAX_TTL_SECONDS + 1_000_000;

        let jwe = vault
            .mint_signing_lease(&host, &backend, &options)
            .await
            .expect("mint must cap rather than reject an over-cap ttl");
        let key = vault.key_manager().get_current_key().unwrap();
        let claims = decrypt_token(&key.key, &jwe).unwrap();

        assert_eq!(
            claims.exp - claims.iat,
            crate::profile::SIGNING_LEASE_MAX_TTL_SECONDS
        );
    }

    #[tokio::test]
    async fn kgen_equals_the_current_key_generation_at_mint() {
        let host = TestHost::new(false);
        let mut vault = init_vault(&host).await;
        let backend = MockSigningBackend {
            capabilities: BackendCapabilities::none(),
        };
        let options = base_options(true, false);

        let first_jwe = vault
            .mint_signing_lease(&host, &backend, &options)
            .await
            .unwrap();
        let key = vault.key_manager().get_current_key().unwrap();
        let first_claims = decrypt_token(&key.key, &first_jwe).unwrap();
        assert_eq!(first_claims.kgen, Some(0));

        vault
            .revoke_lease_key(&host, options.key_name)
            .await
            .expect("revoke_lease_key must persist");

        let second_jwe = vault
            .mint_signing_lease(&host, &backend, &options)
            .await
            .unwrap();
        let key = vault.key_manager().get_current_key().unwrap();
        let second_claims = decrypt_token(&key.key, &second_jwe).unwrap();
        assert_eq!(
            second_claims.kgen,
            Some(1),
            "kgen must reflect the post-revoke generation"
        );
    }

    // --- Claims shape sanity: no val, kty is SigningKey, ref is the
    // --- namespaced backend id (review anchor, not a formal AC) ---

    #[tokio::test]
    async fn minted_lease_carries_no_val_and_is_kty_signing_key() {
        let host = TestHost::new(false);
        let vault = init_vault(&host).await;
        let backend = MockSigningBackend {
            capabilities: BackendCapabilities::none(),
        };
        let options = base_options(true, false);

        let jwe = vault
            .mint_signing_lease(&host, &backend, &options)
            .await
            .unwrap();
        let key = vault.key_manager().get_current_key().unwrap();
        let claims = decrypt_token(&key.key, &jwe).unwrap();

        assert!(claims.val.is_none());
        assert_eq!(claims.kty, Some(ClaimsKind::SigningKey));
        assert_eq!(claims.sub, "release-signer");
        assert_eq!(claims.reference, "signing-key:release-signer");
        assert_eq!(
            claims.kid,
            Some("kid-for-signing-key:release-signer".to_string())
        );
    }
}
