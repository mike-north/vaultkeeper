//! VaultKeeper main struct — wires together all vaultkeeper subsystems.

use std::collections::HashMap;

use crate::backend::{HostPlatform, PresenceOperation, SecretBackend, get_backend_capabilities};
use crate::config;
use crate::errors::{ExecutableTrustRequiredReason, VaultError};
use crate::jwe::{
    CreateTokenOptions, block_token, create_token, decrypt_token, extract_kid, validate_claims,
};
use crate::keys::KeyManager;
use crate::types::{KeyStatus, PreflightResult, VaultClaims, VaultConfig, VaultResponse};

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

/// Main entry point for vaultkeeper. Orchestrates backends, keys, JWE tokens,
/// identity verification, and access patterns.
pub struct VaultKeeper {
    config: VaultConfig,
    key_manager: KeyManager,
    _backend: Option<Box<dyn SecretBackend>>,
    /// Per-JTI usage counts for use-limited tokens.
    usage_counts: HashMap<String, u64>,
    /// Whether key state is persisted to the host's config directory.
    ///
    /// `false` when `VaultKeeperOptions::config` was supplied directly: the
    /// caller is assembling the vault in-process (tests, embedders), so keys
    /// stay in memory only and never touch the config dir — mirroring the TS
    /// `VaultKeeper.init`'s `persistKeys` flag.
    persist_keys: bool,
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
            usage_counts: HashMap::new(),
            persist_keys,
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
            bkd: backend_type,
            val: secret_value.to_string(),
            reference: secret_name.to_string(),
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

    /// Decrypt a JWE token, validate its claims, and return the claims
    /// and key status. Tracks per-JTI usage counts and blocks tokens that
    /// exceed their use limit.
    pub fn authorize(&mut self, jwe: &str) -> Result<(VaultClaims, VaultResponse), VaultError> {
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

        let current_usage = self.usage_counts.get(&claims.jti).copied().unwrap_or(0);
        validate_claims(&claims, current_usage)?;

        // Increment usage count
        let new_usage = current_usage + 1;
        self.usage_counts.insert(claims.jti.clone(), new_usage);

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

        Ok((claims, response))
    }
}
