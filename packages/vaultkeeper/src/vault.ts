/**
 * VaultKeeper main class — wires together all vaultkeeper subsystems.
 */

import * as crypto from 'node:crypto'
import * as path from 'node:path'
import type {
  VaultConfig,
  VaultClaims,
  VaultResponse,
  FetchRequest,
  ExecRequest,
  ExecResult,
  SecretAccessor,
  PreflightResult,
  TrustTier,
  SignRequest,
  SignResult,
  VerifyRequest,
  SigningAlgorithm,
  SigningPublicKey,
} from './types.js'
import { loadConfig, getDefaultConfigDir } from './config.js'
import { KeyManager } from './keys/manager.js'
import { loadKeyState, saveKeyState } from './keys/storage.js'
import { BackendRegistry } from './backend/registry.js'
import { isSigningBackend, getBackendCapabilities } from './backend/types.js'
import type {
  SecretBackend,
  SigningBackend,
  BackendCapabilities,
  PresenceOperation,
} from './backend/types.js'
import { createToken, decryptToken, extractKid, validateClaims, blockToken } from './jwe/index.js'
import { verifyTrustPending, commitTrust } from './identity/trust.js'
import { hashExecutable } from './identity/hash.js'
import { loadManifest, saveManifest, addTrustedHash, isTrusted } from './identity/manifest.js'
import {
  CapabilityToken,
  createCapabilityToken,
  createSigningCapabilityToken,
  validateCapabilityToken,
  isSigningClaims,
} from './identity/session.js'
import { delegatedFetch } from './access/delegated-fetch.js'
import { delegatedExec } from './access/delegated-exec.js'
import { createSecretAccessor } from './access/controlled-direct.js'
import { createDetachedJws, verifyDetachedJws } from './access/jws.js'
import { runDoctor } from './doctor/runner.js'
import type { RunDoctorOptions } from './doctor/runner.js'
import {
  AuthorizationDeniedError,
  IdentityMismatchError,
  ExecutableTrustRequiredError,
  BackendUnavailableError,
  VaultError,
  KeyRevokedError,
  SigningNotSupportedError,
  NotCapableError,
} from './errors.js'

/**
 * Map of named secrets to their capability tokens.
 *
 * Use with `exec()` or `fetch()` to inject multiple secrets into a single
 * request. Each key becomes the name referenced in `{{secret:name}}`
 * placeholders.
 *
 * @example
 * ```ts
 * const { token: apiToken } = await vault.authorize(apiJwe)
 * const { token: dbToken } = await vault.authorize(dbJwe)
 *
 * await vault.exec(
 *   { apiKey: apiToken, dbPass: dbToken },
 *   { command: 'deploy', env: { API_KEY: '{{secret:apiKey}}', DB: '{{secret:dbPass}}' } },
 * )
 * ```
 *
 * @public
 */
export type SecretTokenMap = Record<string, CapabilityToken>

/**
 * Builds a minimal built-in config used when {@link VaultKeeperOptions.backend}
 * is supplied without {@link VaultKeeperOptions.config}. Mirrors the defaults a
 * hand-assembled test config would use (short-lived tokens, dev-mode trust),
 * so an injected backend never requires a config file on disk or a
 * hand-assembled {@link VaultConfig}.
 *
 * Returns a fresh object on every call — `VaultKeeper` mutates `#config` in
 * place (e.g. `setDevelopmentMode()`), so a shared constant would let
 * separate `init()` calls corrupt each other's state.
 */
function createDefaultInjectedBackendConfig(): VaultConfig {
  return {
    version: 1,
    backends: [],
    keyRotation: { gracePeriodDays: 7 },
    defaults: { ttlMinutes: 60, trustTier: 3 },
  }
}

/**
 * Options for initializing VaultKeeper.
 *
 * @remarks
 * When neither `config` nor a config file (at `configDir`) is present, and
 * {@link VaultKeeperOptions.backend} is not set, the active backend falls back
 * to the safe zero-config default resolved by {@link defaultBackendType} — the
 * `file` backend, on every platform, so a missing config never silently
 * targets the real OS credential store. Inspect
 * {@link VaultKeeper.activeBackendType} after `init()` to confirm which backend
 * a given instance resolved to. To use the OS-native store instead, opt in via
 * an explicit config, or `vaultkeeper config init --backend <type>` from the
 * separate `@vaultkeeper/cli` package (see {@link platformNativeBackendType}).
 * When `backend` is set instead, see that option's own JSDoc for the fallback
 * config used in its place.
 */
export interface VaultKeeperOptions {
  /** Override the config directory. */
  configDir?: string | undefined
  /** Supply config directly, skipping file load. */
  config?: VaultConfig | undefined
  /**
   * Inject a {@link SecretBackend} instance directly, bypassing the global
   * {@link BackendRegistry} and `config.backends` resolution entirely.
   *
   * This is the primary hook for tests and embedders that want to store and
   * retrieve secrets without registering a backend globally or hand
   * assembling a full {@link VaultConfig}. When set, this backend instance is
   * used for every `store()`/`retrieve()`/`setup()` call.
   *
   * **Precedence with `config`/`configDir`:**
   * - `backend` always wins over the backend that `config.backends` (or the
   *   config loaded from `configDir`) would otherwise resolve — the
   *   `backends` array is never consulted when `backend` is set.
   * - Other config fields (`keyRotation`, `defaults`, `developmentMode`)
   *   still come from `config`, or from the config loaded from `configDir`,
   *   when either is provided.
   * - If `backend` is set and `config` is omitted, a minimal built-in
   *   default config is used instead of loading one from `configDir` — so a
   *   caller that only needs an injected backend never has to construct a
   *   {@link VaultConfig} or touch `configDir` at all.
   */
  backend?: SecretBackend | undefined
  /** Skip the doctor preflight check. */
  skipDoctor?: boolean | undefined
}

/**
 * Options common to every backend-touching operation that can be gated on a
 * fresh, per-use human presence action.
 *
 * @remarks
 * When `requirePresencePerUse` is `true`, the operation refuses — with a
 * {@link NotCapableError}, before any credential, session, or device is touched
 * — unless the active backend's configured instance advertises
 * {@link BackendCapabilities.presencePerUse}. When the backend is capable, the
 * operation proceeds through the backend's ordinary path, which (by the meaning
 * of the capability) forces a distinct fresh human action for this specific
 * call; a cached or session-unlocked state can never satisfy it. Capabilities
 * are queried fresh on every call and never cached across operations.
 *
 * @public
 */
export interface PresenceRequirementOptions {
  /**
   * Require the active backend to force a fresh, per-use human presence action
   * for this operation. Defaults to `false` (no presence requirement).
   */
  requirePresencePerUse?: boolean | undefined
}

/**
 * Options for {@link VaultKeeper.setup} that are independent of the mandatory
 * executable-trust choice. Intersected with that choice to form
 * {@link SetupOptions}.
 *
 * @public
 */
export interface SetupOptionsBase extends PresenceRequirementOptions {
  /** TTL in minutes for the JWE. */
  ttlMinutes?: number | undefined
  /** Usage limit (null for unlimited). */
  useLimit?: number | null | undefined
  /** Trust tier override. */
  trustTier?: TrustTier | undefined
  /** Backend type to use. */
  backendType?: string | undefined
}

/**
 * Options for the setup operation.
 *
 * @remarks
 * The executable-trust choice is **mandatory and mutually exclusive**, and the
 * type system enforces it: `SetupOptions` is {@link SetupOptionsBase}
 * intersected with a choice of **exactly one** of `executablePath` (run
 * trust-on-first-use verification — the production choice) or `skipTrust: true`
 * (deliberately skip verification — development only). An options object with
 * **neither** field, or with **both**, fails to typecheck; and because
 * {@link VaultKeeper.setup}'s options argument is required, `vault.setup('NAME')`
 * and `vault.setup('NAME', {})` are compile-time type errors rather than
 * runtime-only failures. {@link ExecutableTrustRequiredError} remains a runtime
 * backstop for callers without static typing (e.g. plain JavaScript), and is
 * still thrown if `executablePath` is the retired legacy `'dev'` sentinel.
 *
 * @public
 */
export type SetupOptions = SetupOptionsBase &
  (
    | {
        /**
         * Path to the calling executable, used to bind the minted token to that
         * executable's identity. `setup()` runs trust-on-first-use (TOFU)
         * verification: the file is hashed (SHA-256) and checked against the
         * local trust manifest. This is the safe, production choice.
         *
         * A path registered via `setDevelopmentMode` is still exempted from
         * hashing (the established development-mode allowlist); any other path
         * is verified. Mutually exclusive with `skipTrust`.
         *
         * **Rebuild caveat:** for a compiled or bundled entry point the file's
         * hash changes on every rebuild, so binding to a dev build target (e.g.
         * `process.argv[1]`) makes the next `setup()` after a recompile throw
         * `IdentityMismatchError`. In production point this at a **stable**
         * artifact — a released binary, or `process.execPath` to trust the Node
         * runtime; for a frequently-rebuilt local caller you want to keep
         * verifying, use `setDevelopmentMode` instead.
         */
        executablePath: string
        skipTrust?: never
      }
    | {
        /**
         * Development-only escape hatch: skip executable-trust (TOFU)
         * verification. The minted token carries no executable identity binding.
         *
         * **Security warning:** a token minted with `skipTrust: true` is not
         * bound to any calling executable, so any process that obtains the JWE
         * can redeem it. Use this only in local development or tests — never in
         * production. Prefer `executablePath` so executable trust is actually
         * enforced. Mutually exclusive with `executablePath`.
         */
        skipTrust: true
        executablePath?: never
      }
  )

/**
 * Loose trust-choice shape accepted by the internal resolver. Unlike the public
 * {@link SetupOptions} discriminated union, both fields are independently
 * optional here so the runtime mutual-exclusion / missing-choice backstops stay
 * reachable for untyped (plain-JavaScript) callers.
 */
interface TrustChoiceInput extends SetupOptionsBase {
  executablePath?: string | undefined
  skipTrust?: boolean | undefined
}

/**
 * Trust status of an executable, as recorded in the trust-on-first-use (TOFU)
 * trust manifest.
 *
 * Returned by {@link VaultKeeper.approveExecutable} and
 * {@link VaultKeeper.checkExecutableTrust}.
 *
 * @public
 */
export interface ExecutableTrustStatus {
  /**
   * Whether the executable's current hash is approved in the trust manifest.
   * When `false`, callers must obtain approval (e.g. an interactive prompt)
   * before granting secret access.
   */
  trusted: boolean
  /** SHA-256 hex digest of the executable's current contents. */
  hash: string
  /**
   * `true` when the executable is already known to the manifest but its
   * current hash does not match any approved value — a TOFU conflict. A
   * conflicting executable is never trusted; callers must re-approve or deny.
   */
  hashMismatch: boolean
  /**
   * Hashes recorded as approved for this executable in the trust manifest, in
   * approval order (empty when the executable has never been approved). When
   * {@link ExecutableTrustStatus.hashMismatch} is `true`, these are the prior
   * approved values that {@link ExecutableTrustStatus.hash} no longer matches;
   * the last element is the most recently approved hash.
   */
  approvedHashes: readonly string[]
  /** Human-readable description of how trust was (or was not) established. */
  reason: string
}

/**
 * The **built-in** backend type identifiers known to implement the signing
 * contract ({@link SigningBackend}). Surfaced on {@link SigningNotSupportedError}
 * so a caller on a non-signing backend is pointed at a built-in that works.
 * Deliberately a static list of built-ins — a consumer's own registered
 * SigningBackend is not surveyed here (that would mean instantiating every
 * registered backend on an error path).
 */
const BUILTIN_SIGNING_BACKENDS = ['file'] as const

/**
 * Human-readable guidance naming the kinds of backends that can satisfy a
 * presence-per-use requirement. Surfaced in {@link NotCapableError} messages so
 * a caller whose configured backend cannot provide the guarantee is pointed at
 * ones that can. Deliberately describes qualifying *configurations* (not a fixed
 * type list), since the capability is per configured instance — a custom
 * backend may also qualify.
 */
const PRESENCE_PER_USE_QUALIFYING_BACKENDS =
  'A qualifying backend forces a distinct, fresh human action per operation — ' +
  'e.g. a YubiKey slot with a touch-per-operation policy or a gpg smartcard with ' +
  'touch-to-sign (both cover every operation), or 1Password in per-access mode ' +
  '(which enforces presence for reads only today, not writes). Switch to (or ' +
  'reconfigure) such a backend, or drop the presence requirement.'

/** Usage tracking for tokens with use limits. */
const usageCounts = new Map<string, number>()

/**
 * Maximum number of JTIs the in-memory usage-count map will retain.
 * When the cap is reached, the oldest inserted entry is evicted (FIFO).
 * This prevents unbounded growth for long-running processes.
 */
const USAGE_MAP_MAX_SIZE = 10_000

/**
 * Main entry point for vaultkeeper. Orchestrates backends, keys, JWE tokens,
 * identity verification, and access patterns.
 */
export class VaultKeeper {
  readonly #config: VaultConfig
  readonly #keyManager: KeyManager
  readonly #configDir: string
  /**
   * Whether key material is persisted to (and reloaded from) `#configDir`.
   * Enabled only when the vault operates against a real on-disk config — i.e.
   * neither `config` nor `backend` was injected in-process (see
   * {@link VaultKeeper.init}). Injected-config/backend instances keep keys
   * purely in memory so tests and embedders stay hermetic.
   */
  readonly #persistKeys: boolean
  #backend: SecretBackend | undefined
  /**
   * Whether {@link #backend} was injected via `init({ backend })` rather than
   * lazily resolved from `#config.backends`. Distinguishes the two so that
   * {@link activeBackendType} reports the injected instance directly instead of
   * consulting the (empty) config backend list. Stays correct after a lazy
   * resolution populates {@link #backend} in the config-driven path.
   */
  readonly #backendInjected: boolean

  private constructor(
    config: VaultConfig,
    keyManager: KeyManager,
    configDir: string,
    persistKeys: boolean,
    backend?: SecretBackend,
  ) {
    this.#config = config
    this.#keyManager = keyManager
    this.#configDir = configDir
    this.#persistKeys = persistKeys
    this.#backend = backend
    this.#backendInjected = backend !== undefined
  }

  /**
   * Initialize a new VaultKeeper instance.
   * Runs doctor checks (unless skipped), loads config, and sets up the key manager.
   *
   * The configured secret backend is resolved lazily on first use, not during
   * `init()`. Trust-only operations (e.g. {@link VaultKeeper.approveExecutable},
   * {@link VaultKeeper.checkExecutableTrust}) therefore succeed even when the
   * configured backend or plugin is unavailable or unregistered; a
   * misconfigured backend surfaces only when a secret operation is invoked.
   */
  static async init(options?: VaultKeeperOptions): Promise<VaultKeeper> {
    const configDir = options?.configDir ?? getDefaultConfigDir()
    const config =
      options?.config ??
      (options?.backend !== undefined
        ? createDefaultInjectedBackendConfig()
        : await loadConfig(configDir))

    if (options?.skipDoctor !== true) {
      const doctorResult = await runDoctor({ backends: config.backends })
      if (!doctorResult.ready) {
        throw new VaultError(`System not ready: ${doctorResult.nextSteps.join('; ')}`)
      }
    }

    // Persist key material to disk only when operating against a real on-disk
    // config directory. When either `config` or `backend` is injected, the
    // caller is assembling the vault in-process (tests, embedders), so keys stay
    // in memory and never touch the config dir.
    const persistKeys = options?.config === undefined && options?.backend === undefined

    const keyManager = new KeyManager()
    if (persistKeys) {
      const loaded = await loadKeyState(configDir)
      if (loaded !== undefined) {
        keyManager.hydrate(loaded)
      } else {
        await keyManager.init()
        await saveKeyState(configDir, keyManager.snapshot())
      }
    } else {
      await keyManager.init()
    }

    return new VaultKeeper(config, keyManager, configDir, persistKeys, options?.backend)
  }

  /**
   * Run doctor checks without full initialization.
   *
   * When called without arguments, uses conservative platform defaults —
   * all platform-native dependency checks are treated as required. Pass
   * `{ backends }` to scope checks to only the backends you plan to use.
   *
   * @param options - Optional doctor options (e.g. `{ backends }` to scope checks).
   */
  static async doctor(options?: RunDoctorOptions): Promise<PreflightResult> {
    return runDoctor(options)
  }

  /**
   * The type identifier of the active backend — the first enabled backend in
   * the resolved configuration (the one `store()`, `delete()`, and `setup()`
   * operate on).
   *
   * @remarks
   * This is a pure, side-effect-free view of the resolved configuration: it
   * reads the type of the first enabled backend without instantiating the
   * backend or requiring it to be registered or healthy. Reading it therefore
   * never throws for an unavailable or unregistered backend — unlike a secret
   * operation — so it is safe to call purely to introspect an instance.
   *
   * When a backend was injected via `init({ backend })`, config-based
   * resolution is bypassed entirely and this reports the injected instance's
   * declared `type` (see {@link SecretBackend}) — or the stable sentinel
   * `'custom'` if it declares an empty type. It never throws in the injected
   * path.
   *
   * Use it to confirm which backend an instance resolved to, especially when
   * no config file exists and the safe zero-config default applies (see
   * {@link defaultBackendType}). With no config this reads `file` on every
   * platform, so secret operations never silently target the real OS
   * credential store; opt into the native store (see
   * {@link platformNativeBackendType}) via explicit config to change this.
   *
   * @throws A {@link BackendUnavailableError} only when the configuration has
   * no enabled backend at all (a configuration error, not a backend fault).
   * This can only happen in the config-driven path; an injected backend never
   * throws here.
   *
   * @public
   */
  get activeBackendType(): string {
    if (this.#backendInjected && this.#backend !== undefined) {
      // An injected backend wins over config resolution (see init()); report
      // its declared type, falling back to a stable sentinel if it declares none.
      return VaultKeeper.#resolveBackendTypeHint(this.#backend)
    }
    const firstEnabled = this.#config.backends.find((b) => b.enabled)
    if (firstEnabled === undefined) {
      throw new BackendUnavailableError(
        'No enabled backends configured',
        'none-enabled',
        this.#config.backends.map((b) => b.type),
      )
    }
    return firstEnabled.type
  }

  /**
   * Report the {@link BackendCapabilities} of the active backend's configured
   * instance — the same backend {@link VaultKeeper.store}, {@link VaultKeeper.setup},
   * and {@link VaultKeeper.sign} operate on.
   *
   * @remarks
   * Unlike the pure {@link VaultKeeper.activeBackendType} getter, this resolves
   * (instantiates) the backend, because capabilities are a property of the
   * configured instance, not of the type. The answer reflects configured/live
   * state — e.g. a YubiKey slot's touch policy or 1Password's access mode — and
   * a backend that does not implement {@link PresenceCapableBackend} reports the
   * safe default (`{ presencePerUse: false }`) via {@link getBackendCapabilities}.
   * Reading this never triggers a human-presence prompt.
   *
   * @returns The active backend instance's capabilities.
   * @throws A {@link BackendUnavailableError} if no backend is enabled or the
   *   configured backend cannot be built.
   * @public
   */
  async getActiveBackendCapabilities(): Promise<BackendCapabilities> {
    const backend = this.#requireBackend()
    return getBackendCapabilities(backend)
  }

  /**
   * Store a secret in the configured backend.
   *
   * This is a convenience method that delegates to the active backend's
   * `store()` method. If a secret with the same name already exists, it is
   * overwritten.
   *
   * @param name - Identifier for the secret. Must not contain `':'` — that
   *   character is reserved for the internal `signing-key:` namespace, so a
   *   secret name can never collide with a signing key.
   * @param value - The secret value to store.
   * @param options - Optional {@link PresenceRequirementOptions}. When
   *   `requirePresencePerUse` is set, the store is refused with a
   *   {@link NotCapableError} before the backend is touched unless the active
   *   backend forces a fresh per-use human action.
   * @throws {VaultError} If `name` is empty or contains `':'`.
   * @throws {@link NotCapableError} If `options.requirePresencePerUse` is set
   *   and the active backend is not presence-per-use capable.
   * @public
   */
  async store(name: string, value: string, options?: PresenceRequirementOptions): Promise<void> {
    VaultKeeper.#validateName(name, 'secret')
    const backend = this.#requireBackend()
    await this.#enforcePresenceRequirement(backend, 'store', options?.requirePresencePerUse)
    await backend.store(name, value)
  }

  /**
   * Delete a secret from the configured backend.
   *
   * This is a convenience method that delegates to the active backend's
   * `delete()` method.
   *
   * @param name - Identifier for the secret to delete.
   * @param options - Optional {@link PresenceRequirementOptions}. When
   *   `requirePresencePerUse` is set, the delete is refused with a
   *   {@link NotCapableError} before the backend is touched unless the active
   *   backend forces a fresh per-use human action.
   * @throws {@link NotCapableError} If `options.requirePresencePerUse` is set
   *   and the active backend is not presence-per-use capable.
   * @public
   */
  async delete(name: string, options?: PresenceRequirementOptions): Promise<void> {
    // Permissive: a legacy secret whose name contains ':' must remain deletable.
    VaultKeeper.#validateName(name, 'secret', false)
    const backend = this.#requireBackend()
    await this.#enforcePresenceRequirement(backend, 'delete', options?.requirePresencePerUse)
    await backend.delete(name)
  }

  /**
   * Check whether a secret exists in the active backend, without retrieving
   * its value, minting a token, or touching the TOFU trust manifest.
   *
   * @remarks
   * This is a lightweight precondition check intended to run before any
   * interactive or trust-gating logic (e.g. `exec`'s caller-approval prompt),
   * so a nonexistent secret is reported immediately and unambiguously instead
   * of being masked by an unrelated approval failure — see issue #69.
   *
   * @param name - Identifier for the secret.
   * @returns `true` if the secret exists, `false` otherwise.
   * @public
   */
  async secretExists(name: string): Promise<boolean> {
    // Permissive: a legacy secret whose name contains ':' must remain checkable.
    VaultKeeper.#validateName(name, 'secret', false)
    const backend = this.#requireBackend()
    return backend.exists(name)
  }

  /**
   * Read a stored secret from the backend and mint a JWE token that encapsulates it.
   *
   * @remarks
   * `setup()` requires an explicit executable-trust decision — it has no
   * default and never silently skips verification. Pass `executablePath` (the
   * calling executable's real path) to run trust-on-first-use verification, or
   * `skipTrust: true` to deliberately skip it in development. The {@link SetupOptions}
   * type enforces this choice at compile time (exactly one, and the options
   * argument is required); {@link ExecutableTrustRequiredError} is the runtime
   * backstop for untyped callers.
   *
   * @example
   * ```ts
   * // Production: bind the token to a STABLE executable so a swapped binary is
   * // rejected. Point executablePath at a released binary, or process.execPath
   * // to trust the Node runtime. Do NOT use process.argv[1] for a compiled entry
   * // point — its hash changes on every rebuild, so the next setup() after a
   * // recompile throws IdentityMismatchError (use setDevelopmentMode or
   * // skipTrust for a frequently-rebuilt local caller).
   * const jwe = await vault.setup('MY_API_KEY', { executablePath: '/usr/local/bin/my-tool' })
   *
   * // Local development: skip verification so rebuilds don't reject the caller.
   * const devJwe = await vault.setup('MY_API_KEY', { skipTrust: true })
   * ```
   *
   * @param secretName - Identifier for the secret. Must not contain `':'` (the
   *   reserved `signing-key:` namespace separator).
   * @param options - Setup options; must carry exactly one of `executablePath`
   *   or `skipTrust: true`
   * @returns Compact JWE string
   * @throws {VaultError} If `secretName` is empty or contains `':'`.
   * @throws {@link ExecutableTrustRequiredError} If neither `executablePath`
   *   nor `skipTrust: true` is provided, if both are, or if `executablePath` is
   *   the retired legacy `'dev'` opt-out sentinel (use `skipTrust: true`).
   * @throws {@link IdentityMismatchError} If `executablePath`'s current hash no
   *   longer matches a previously approved value (TOFU conflict).
   * @throws {@link FilesystemError} If `executablePath` cannot be read or hashed
   *   for verification, or the trust manifest cannot be read or written while
   *   recording the executable.
   */
  async setup(secretName: string, options: SetupOptions): Promise<string> {
    VaultKeeper.#validateName(secretName, 'secret')
    const backend = this.#requireBackend()

    // Resolve (and validate) the executable-trust choice first — before reading
    // any option field or touching the backend — so a malformed call fails fast
    // without a secret read. This also guards the runtime backstop: an untyped
    // (plain-JavaScript) caller can pass `undefined` despite the required type,
    // and this call throws ExecutableTrustRequiredError instead of dereferencing
    // `undefined`. Past this point `options` is guaranteed present.
    //
    // This only *verifies* trust; a first-encounter (TOFU) or Sigstore hash is
    // staged, not written yet. The manifest write is deferred via
    // `commitExecutableTrust` until the whole operation succeeds below — see
    // issue #148 (a failed setup() must never durably pre-seed TOFU trust).
    const { exeIdentity, commit: commitExecutableTrust } =
      await this.#resolveExecutableIdentity(options)

    // Enforce a presence-per-use requirement before the backend secret read
    // below — an unsatisfiable requirement fails fast with a NotCapableError
    // without ever touching a credential/session. This runs after the trust
    // resolution above (which throws for a missing choice), so `options` is
    // guaranteed present here and no credential has been touched yet. The
    // operation is 'read' — setup reads the stored secret to mint a token.
    await this.#enforcePresenceRequirement(backend, 'read', options.requirePresencePerUse)

    const backendType = VaultKeeper.#resolveBackendTypeHint(backend, options.backendType)
    const ttlMinutes = options.ttlMinutes ?? this.#config.defaults.ttlMinutes
    const trustTier = options.trustTier ?? this.#config.defaults.trustTier
    const useLimit = options.useLimit ?? null

    const secretValue = await backend.retrieve(secretName)

    const now = Math.floor(Date.now() / 1000)
    const claims: VaultClaims = {
      jti: crypto.randomUUID(),
      exp: now + ttlMinutes * 60,
      iat: now,
      sub: secretName,
      exe: exeIdentity,
      use: useLimit,
      tid: trustTier,
      bkd: backendType,
      val: secretValue,
      ref: secretName,
    }

    const currentKey = this.#keyManager.getCurrentKey()
    const token = createToken(currentKey.key, claims, { kid: currentKey.id })

    // Only now that the secret was retrieved and the token minted does a
    // first-encounter (or Sigstore) trust decision become a durable manifest
    // write. A failure anywhere above (e.g. SecretNotFoundError) leaves the
    // trust manifest untouched.
    await commitExecutableTrust()

    return token
  }

  /**
   * Decrypt a JWE, validate claims, verify executable identity, and return
   * an opaque CapabilityToken.
   *
   * @param jwe - Compact JWE string from setup()
   * @returns Object containing an opaque {@link CapabilityToken} for use with
   *   fetch/exec/getSecret, and a {@link VaultResponse} describing key status.
   *   When the JWE was decrypted with a non-current key,
   *   `vaultResponse.rotatedJwt` contains a re-encrypted JWE for the current key.
   */
  async authorize(jwe: string): Promise<{ token: CapabilityToken; vaultResponse: VaultResponse }> {
    const kid = extractKid(jwe)
    const { claims, keyStatus } = await this.#decryptWithKeyResolution(jwe, kid)

    // Validate claims (expiry, blocklist, usage)
    const jti = claims.jti
    const currentCount = usageCounts.get(jti) ?? 0
    validateClaims(claims, currentCount)

    // Only track usage for tokens with a finite use limit. Unlimited tokens
    // (claims.use === null) never need count checks, so tracking them would
    // waste memory and cause unnecessary evictions of limited-token entries.
    if (claims.use !== null) {
      const newCount = currentCount + 1
      usageCounts.set(jti, newCount)

      // Evict the oldest entry when the map exceeds its size cap to prevent
      // unbounded memory growth in long-running processes. Block the evicted
      // JTI so that it cannot be silently re-authorized with a reset count.
      if (usageCounts.size > USAGE_MAP_MAX_SIZE) {
        const oldest = usageCounts.keys().next().value
        if (oldest !== undefined) {
          usageCounts.delete(oldest)
          blockToken(oldest)
        }
      }
    }

    const token = createCapabilityToken(claims)

    const vaultResponse: VaultResponse = { keyStatus }
    if (keyStatus === 'previous') {
      // Re-encrypt with current key
      const currentKey = this.#keyManager.getCurrentKey()
      const rotatedJwt = await createToken(currentKey.key, claims, { kid: currentKey.id })
      vaultResponse.rotatedJwt = rotatedJwt
    }

    return { token, vaultResponse }
  }

  /**
   * Execute a delegated HTTP fetch, injecting secrets from the token(s).
   *
   * **Single token:** every `{{secret}}` placeholder in `request.url`,
   * `request.headers`, and `request.body` is replaced with the secret value.
   *
   * **Token map ({@link SecretTokenMap}):** every `{{secret:name}}` placeholder
   * is replaced with the secret from the corresponding named token.
   *
   * The raw secret is never exposed in the return value.
   *
   * @param token - A single `CapabilityToken` or a `SecretTokenMap` mapping
   *   names to tokens obtained from `authorize()`.
   * @param request - The fetch request template with placeholders.
   * @returns The `Response` from the underlying `fetch()` call, together with
   *   the vault metadata (`vaultResponse`).
   * @throws {AuthorizationDeniedError} If any token is invalid or was not
   *   created by this vault instance.
   * @throws {VaultError} If a named placeholder references an unknown
   *   secret name.
   * @throws {FetchError} If the URL is malformed or the underlying network
   *   request fails.
   */
  async fetch(
    token: CapabilityToken | SecretTokenMap,
    request: FetchRequest,
  ): Promise<{ response: Response; vaultResponse: VaultResponse }> {
    const secrets = VaultKeeper.#resolveSecrets(token)
    const response = await delegatedFetch(secrets, request)
    return {
      response,
      vaultResponse: { keyStatus: 'current' },
    }
  }

  /**
   * Execute a delegated command, injecting secrets from the token(s).
   *
   * **Single token:** every `{{secret}}` placeholder in `request.env` values
   * is replaced with the secret value.
   *
   * **Token map ({@link SecretTokenMap}):** every `{{secret:name}}` placeholder
   * is replaced with the secret from the corresponding named token.
   *
   * Secret placeholders are not supported in `request.command` or
   * `request.args` — process arguments are visible to other processes via
   * `ps` and often collected in logs and telemetry.
   *
   * The raw secret is never exposed in the return value: by default the
   * captured `stdout`/`stderr` is scrubbed of every injected secret value
   * (replaced with `[REDACTED]`), so a command that echoes the secret does not
   * leak it back. Pass `request.redact = false` to receive raw, unredacted
   * output — only when a caller genuinely needs it, since that forfeits the
   * guarantee.
   *
   * @param token - A single `CapabilityToken` or a `SecretTokenMap` mapping
   *   names to tokens obtained from `authorize()`.
   * @param request - The exec request template with placeholders. Set
   *   `redact: false` to opt out of output redaction.
   * @returns The command result (`stdout`, `stderr`, `exitCode`) together with
   *   the vault metadata (`vaultResponse`).
   * @throws {AuthorizationDeniedError} If any token is invalid or was not
   *   created by this vault instance.
   * @throws {ExecError} If the command cannot be started (e.g. ENOENT),
   *   a placeholder references an unknown secret name, or a secret
   *   placeholder appears in the `command` or `args` field.
   */
  async exec(
    token: CapabilityToken | SecretTokenMap,
    request: ExecRequest,
  ): Promise<{ result: ExecResult; vaultResponse: VaultResponse }> {
    const secrets = VaultKeeper.#resolveSecrets(token)
    const result = await delegatedExec(secrets, request)
    return {
      result,
      vaultResponse: { keyStatus: 'current' },
    }
  }

  /**
   * Create a controlled-direct `SecretAccessor` from a capability token.
   *
   * The accessor wraps the secret in a single-use, auto-zeroing `Buffer`. The
   * secret is accessible only through the `read()` callback and is zeroed
   * immediately after the callback returns.
   *
   * @param token - A `CapabilityToken` obtained from `authorize()`.
   * @returns A `SecretAccessor` that can be read exactly once.
   * @throws {AuthorizationDeniedError} If `token` is invalid or was not created
   *   by this vault instance, or if it is a signing-key token — a signing key
   *   carries no secret and cannot be read through `getSecret()` (use `sign()`).
   */
  getSecret(token: CapabilityToken): SecretAccessor {
    const claims = validateCapabilityToken(token)
    // Defense in depth: a signing-key token carries no secret and must never be
    // read through the secret-access path.
    if (isSigningClaims(claims)) {
      throw new AuthorizationDeniedError(
        'This capability token authorizes a signing key, not a secret — ' +
          'it cannot be read with getSecret(). Use sign() instead.',
      )
    }
    return createSecretAccessor(claims.val)
  }

  /**
   * Enroll a new signing keypair under `name` in the active backend.
   *
   * The keypair is generated and stored entirely backend-side (see
   * {@link SigningBackend}); the private key never enters vault claims, a
   * capability token, or the caller's process. Signing keys occupy a namespace
   * distinct from secrets, so a signing key and a secret can share a name
   * without colliding, and a signing key can never be read as a secret.
   *
   * @param name - Caller-facing signing key name. Must not contain `':'` (the
   *   `signing-key:` namespace separator).
   * @param algorithm - The JOSE signing algorithm (currently only `'EdDSA'`).
   * @returns The public half of the newly enrolled key.
   * @throws {SigningNotSupportedError} If the active backend cannot sign.
   * @throws {InvalidAlgorithmError} If `algorithm` is not supported.
   * @throws {SigningKeyAlreadyExistsError} If a signing key already exists under `name`.
   * @throws {VaultError} If `name` is empty or contains `':'`.
   * @public
   */
  async createSigningKey(name: string, algorithm: SigningAlgorithm): Promise<SigningPublicKey> {
    VaultKeeper.#validateName(name, 'signing key')
    const backend = this.#requireSigningBackend()
    const id = VaultKeeper.#signingKeyId(name)
    // The backend validates the algorithm (throws InvalidAlgorithmError) — it is
    // the authority on which algorithms it can generate keys for.
    await backend.generateSigningKey(id, algorithm)
    return backend.getPublicKey(id)
  }

  /**
   * Export the SPKI PEM public key for the signing key named `name`.
   *
   * @param name - Caller-facing signing key name. Must not contain `':'`.
   * @returns The public key material (SPKI PEM, algorithm, kid).
   * @throws {SigningNotSupportedError} If the active backend cannot sign.
   * @throws {SigningKeyNotFoundError} If no signing key exists under `name`.
   * @throws {VaultError} If `name` is empty or contains `':'`.
   * @public
   */
  async exportPublicKey(name: string): Promise<SigningPublicKey> {
    VaultKeeper.#validateName(name, 'signing key')
    const backend = this.#requireSigningBackend()
    return backend.getPublicKey(VaultKeeper.#signingKeyId(name))
  }

  /**
   * Mint a signing-key capability token for the key named `name`.
   *
   * The returned token carries only `{ kid, backendRef, keyType: 'signing-key' }`
   * — never any key material — and is accepted only by {@link VaultKeeper.sign}.
   * Passing it to `getSecret`/`fetch`/`exec` is rejected.
   *
   * @param name - Caller-facing signing key name. Must not contain `':'`.
   * @returns An opaque {@link CapabilityToken} usable with `sign()`.
   * @throws {SigningNotSupportedError} If the active backend cannot sign.
   * @throws {SigningKeyNotFoundError} If no signing key exists under `name`.
   * @throws {VaultError} If `name` is empty or contains `':'`.
   * @public
   */
  async authorizeSigningKey(name: string): Promise<CapabilityToken> {
    VaultKeeper.#validateName(name, 'signing key')
    const backend = this.#requireSigningBackend()
    const id = VaultKeeper.#signingKeyId(name)
    // getPublicKey validates the key exists (throws SigningKeyNotFoundError).
    const pub = await backend.getPublicKey(id)
    return createSigningCapabilityToken({ keyType: 'signing-key', kid: pub.kid, backendRef: id })
  }

  /**
   * Sign a caller-supplied payload with a signing-key capability token.
   *
   * The signature is produced backend-side via {@link SigningBackend.signWithKey}
   * — the private key never leaves the backend and never appears in the token,
   * the claims, or this process. The result is a detached-payload Compact JWS
   * (RFC 7515 §7.2.2 + RFC 7797 `b64:false`, `crit:["b64"]`, `alg:EdDSA`) that
   * any standards-compliant JOSE library can verify given the payload and the
   * public key.
   *
   * @param token - A signing-key `CapabilityToken` from {@link VaultKeeper.authorizeSigningKey}.
   * @param request - The payload to sign.
   * @param options - Optional {@link PresenceRequirementOptions}. When
   *   `requirePresencePerUse` is set, the signature is refused with a
   *   {@link NotCapableError} before the backend is touched unless the active
   *   backend forces a fresh per-use human action. When capable, a fresh
   *   backend `signWithKey` round-trip is performed for this call — no cached
   *   key material can satisfy it (the private key never leaves the backend).
   * @returns The detached compact JWS and vault metadata.
   * @throws {AuthorizationDeniedError} If `token` is invalid or is not a
   *   signing-key token (e.g. an ordinary secret token).
   * @throws {SigningNotSupportedError} If the active backend cannot sign.
   * @throws {SigningKeyNotFoundError} If the referenced key no longer exists.
   * @throws {@link NotCapableError} If `options.requirePresencePerUse` is set
   *   and the active backend is not presence-per-use capable.
   * @public
   */
  async sign(
    token: CapabilityToken,
    request: SignRequest,
    options?: PresenceRequirementOptions,
  ): Promise<{ result: SignResult; vaultResponse: VaultResponse }> {
    const claims = validateCapabilityToken(token)
    if (!isSigningClaims(claims)) {
      throw new AuthorizationDeniedError(
        'sign() requires a signing-key capability token from authorizeSigningKey() — ' +
          'an ordinary secret token cannot be used to sign.',
      )
    }
    const backend = this.#requireSigningBackend()
    await this.#enforcePresenceRequirement(backend, 'sign', options?.requirePresencePerUse)
    const jws = await createDetachedJws(claims.kid, request.payload, (data) =>
      backend.signWithKey(claims.backendRef, data),
    )
    return {
      result: { jws },
      vaultResponse: { keyStatus: 'current' },
    }
  }

  /**
   * Verify a detached-payload Compact JWS against a public key — fully offline.
   *
   * This is a static, asynchronous method: no VaultKeeper instance, backend,
   * config, or capability token is required, so it is safe to call in CI or any
   * context holding only public material.
   *
   * Returns `false` for a signature that does not verify — a tampered payload,
   * the wrong key, or a structurally malformed JWS. It throws
   * {@link InvalidKeyMaterialError} only when the public key itself is not
   * parseable (or a private key was supplied) — an operational fault distinct
   * from a bad signature.
   *
   * @param request - The detached payload, the JWS, and the SPKI PEM public key.
   * @returns `true` if the signature is valid, `false` otherwise.
   * @throws {InvalidKeyMaterialError} If `request.publicKey` is not parseable
   *   SPKI public key material.
   * @public
   */
  static async verify(request: VerifyRequest): Promise<boolean> {
    return verifyDetachedJws(request)
  }

  /**
   * Resolve the active backend and assert it implements the signing contract.
   * @throws {SigningNotSupportedError} If the active backend cannot sign.
   */
  #requireSigningBackend(): SigningBackend {
    const backend = this.#requireBackend()
    if (!isSigningBackend(backend)) {
      throw new SigningNotSupportedError(
        `The active backend ('${backend.type}') does not implement the signing contract. ` +
          `The built-in '${BUILTIN_SIGNING_BACKENDS.join("', '")}' backend does, and a custom ` +
          'backend may implement SigningBackend.',
        backend.type,
        [...BUILTIN_SIGNING_BACKENDS],
      )
    }
    return backend
  }

  /**
   * Shared enforcement for a presence-per-use requirement, called at the top of
   * every backend-touching access path ({@link VaultKeeper.store},
   * {@link VaultKeeper.delete}, {@link VaultKeeper.setup}, {@link VaultKeeper.sign}).
   *
   * @remarks
   * This is the single, non-bypassable point of enforcement — deliberately not
   * duplicated per CLI command. When `require` is not `true` it is a no-op.
   * Otherwise it queries the backend's capabilities **fresh on every call**
   * (never cached across operations, so a prior satisfied call can never
   * satisfy a later one) and throws {@link NotCapableError} — before the caller
   * performs any credential/session/device operation — when the configured
   * instance does not advertise {@link BackendCapabilities.presencePerUse}, **or**
   * advertises it but does not force a fresh action for **this** `operation` (see
   * {@link BackendCapabilities.presenceEnforcedOperations}). The latter makes
   * enforcement operation-aware and fail-closed: e.g. 1Password `per-access`
   * forces presence for reads but not `store`/`delete`, so a flagged write is
   * refused here rather than silently passing through the cached session client.
   *
   * When the backend *is* capable for this operation, this returns and the
   * caller proceeds to the backend's ordinary operation, which by the meaning of
   * the capability forces a distinct fresh human action for this specific call.
   * The presence action itself (and any {@link PresenceDeclinedError}/
   * {@link PresenceTimeoutError}) therefore surfaces from that backend operation,
   * not from here — so two consecutive required-presence operations each drive
   * their own backend call and each demand their own fresh action.
   *
   * @throws {@link NotCapableError} If `require` is `true` and the backend either
   *   is not presence-per-use capable or does not force presence for `operation`.
   */
  async #enforcePresenceRequirement(
    backend: SecretBackend,
    operation: PresenceOperation,
    require: boolean | undefined,
  ): Promise<void> {
    if (require !== true) {
      return
    }
    const capabilities = await getBackendCapabilities(backend)
    if (!capabilities.presencePerUse) {
      throw new NotCapableError(
        `This operation required presence-per-use, but the active backend ` +
          `('${backend.type}') cannot guarantee it. ${PRESENCE_PER_USE_QUALIFYING_BACKENDS}`,
        backend.type,
        'presencePerUse',
      )
    }
    // Operation-aware, fail-closed: a capable instance that only forces presence
    // for some operations (an explicit `presenceEnforcedOperations` list) must
    // refuse a flagged operation it does not cover, rather than passing without a
    // fresh action. An omitted list means "all keyed operations" (a touch device).
    const enforced = capabilities.presenceEnforcedOperations
    if (enforced !== undefined && !enforced.includes(operation)) {
      throw new NotCapableError(
        `This '${operation}' operation required presence-per-use, but the active backend ` +
          `('${backend.type}') only enforces a fresh per-use action for ` +
          `[${enforced.join(', ')}] — not '${operation}'. ${PRESENCE_PER_USE_QUALIFYING_BACKENDS}`,
        backend.type,
        'presencePerUse',
      )
    }
  }

  /** Map a caller-facing signing key name to its namespaced backend id. */
  static #signingKeyId(name: string): string {
    return `signing-key:${name}`
  }

  /**
   * Rotate the current encryption key.
   *
   * The previous key remains valid for decryption during the grace period
   * configured in `keyRotation.gracePeriodDays`. JWEs presented during the
   * grace period return a `rotatedJwt` in the `VaultResponse` so callers can
   * persist the updated token.
   *
   * @throws {RotationInProgressError} If a rotation is already in progress
   *   (i.e. a previous key is still within its grace period).
   */
  async rotateKey(): Promise<void> {
    const gracePeriodMs = this.#config.keyRotation.gracePeriodDays * 24 * 60 * 60 * 1000
    // Throws RotationInProgressError synchronously if a prior rotation's grace
    // period is still active — including one persisted by an earlier process.
    this.#keyManager.rotateKey(gracePeriodMs)
    await this.#persistKeyState()
  }

  /**
   * Emergency key revocation — invalidates the previous key immediately.
   *
   * After revocation, any JWE that was encrypted with the revoked key will
   * be permanently unreadable. A new encryption key is generated automatically
   * so that `setup()` can be called immediately after revocation.
   */
  async revokeKey(): Promise<void> {
    this.#keyManager.revokeKey()
    await this.#persistKeyState()
  }

  /**
   * Persist the current key state to the config dir when persistence is
   * enabled. A no-op for injected-config/backend instances (in-memory keys).
   */
  async #persistKeyState(): Promise<void> {
    if (!this.#persistKeys) {
      return
    }
    await saveKeyState(this.#configDir, this.#keyManager.snapshot())
  }

  /**
   * Add or remove an executable from the development-mode whitelist.
   *
   * When an executable is in the development-mode list, identity verification
   * (TOFU hash checking) is skipped for that executable during `setup()`. This
   * is intended for local development workflows where the binary changes
   * frequently.
   *
   * @param executablePath - Absolute path to the executable to add or remove.
   * @param enabled - Pass `true` to add the executable to the list, `false`
   *   to remove it.
   */
  async setDevelopmentMode(executablePath: string, enabled: boolean): Promise<void> {
    if (this.#config.developmentMode === undefined) {
      if (enabled) {
        this.#config.developmentMode = { executables: [executablePath] }
      }
      return
    }

    const exes = this.#config.developmentMode.executables
    const idx = exes.indexOf(executablePath)

    if (enabled && idx === -1) {
      exes.push(executablePath)
    } else if (!enabled && idx !== -1) {
      exes.splice(idx, 1)
    }

    await Promise.resolve()
  }

  /**
   * Approve an executable for trust-on-first-use by recording its current
   * SHA-256 hash in the trust manifest.
   *
   * After approval, {@link VaultKeeper.setup} and
   * {@link VaultKeeper.checkExecutableTrust} recognize the executable (matched
   * by its resolved absolute path and content hash) as trusted, so callers can
   * skip an interactive approval prompt.
   *
   * The operation is idempotent: approving the same, unchanged executable more
   * than once leaves a single manifest entry.
   *
   * @param executablePath - Path to the executable to approve. Resolved to an
   *   absolute path before hashing and recording.
   * @returns The recorded trust status (always `trusted: true`).
   * @throws {FilesystemError} If the executable does not exist or cannot be read.
   * @public
   */
  async approveExecutable(executablePath: string): Promise<ExecutableTrustStatus> {
    const resolved = path.resolve(executablePath)
    const hash = await hashExecutable(resolved)
    const manifest = await loadManifest(this.#configDir)
    const updated = addTrustedHash(manifest, resolved, hash)
    await saveManifest(this.#configDir, updated)
    return {
      trusted: true,
      hash,
      hashMismatch: false,
      approvedHashes: updated.get(resolved)?.hashes ?? [hash],
      reason: 'Hash recorded in trust manifest',
    }
  }

  /**
   * Check whether an executable is trusted according to the trust manifest,
   * without modifying the manifest.
   *
   * This is a read-only probe. Unlike {@link VaultKeeper.setup}, it never
   * records a hash, so it can be used to decide whether an interactive approval
   * prompt is required before proceeding.
   *
   * @param executablePath - Path to the executable to check. Resolved to an
   *   absolute path before hashing and lookup.
   * @returns The current trust status. `trusted` is `true` only when the
   *   executable's current hash matches an approved manifest entry.
   * @throws {FilesystemError} If the executable does not exist or cannot be read.
   * @public
   */
  async checkExecutableTrust(executablePath: string): Promise<ExecutableTrustStatus> {
    const resolved = path.resolve(executablePath)
    const hash = await hashExecutable(resolved)
    const manifest = await loadManifest(this.#configDir)
    const approvedHashes = manifest.get(resolved)?.hashes ?? []

    if (isTrusted(manifest, resolved, hash)) {
      return {
        trusted: true,
        hash,
        hashMismatch: false,
        approvedHashes,
        reason: 'Hash found in trust manifest',
      }
    }

    const hashMismatch = approvedHashes.length > 0
    return {
      trusted: false,
      hash,
      hashMismatch,
      approvedHashes,
      reason: hashMismatch
        ? 'Executable hash changed from a previously approved value — re-approval required'
        : 'Executable not yet approved',
    }
  }

  // ---------------------------------------------------------------------------
  // Private helpers
  // ---------------------------------------------------------------------------

  static #resolveSecrets(token: CapabilityToken | SecretTokenMap): string | Record<string, string> {
    if (token instanceof CapabilityToken) {
      return VaultKeeper.#requireSecretClaims(token).val
    }
    const result: Record<string, string> = {}
    for (const [name, t] of Object.entries(token)) {
      if (!(t instanceof CapabilityToken)) {
        throw new AuthorizationDeniedError(
          `Invalid capability token for secret "${name}" — expected a CapabilityToken from authorize()`,
        )
      }
      result[name] = VaultKeeper.#requireSecretClaims(t).val
    }
    return result
  }

  /**
   * Resolve a token to its secret claims, rejecting a signing-key token.
   *
   * Defense in depth: a signing-key capability must never be injectable as a
   * secret through `fetch()`/`exec()`.
   */
  static #requireSecretClaims(token: CapabilityToken): VaultClaims {
    const claims = validateCapabilityToken(token)
    if (isSigningClaims(claims)) {
      throw new AuthorizationDeniedError(
        'This capability token authorizes a signing key, not a secret — ' +
          'it cannot be injected into fetch() or exec().',
      )
    }
    return claims
  }

  /**
   * Validate a caller-supplied resource name. `kind` names the resource in the
   * error so a signing-key caller is not told about a "secret".
   *
   * When `enforceReserved` is true (the default, used by name-creating/binding
   * paths — `store`/`setup` and every signing-key operation), the name may not
   * contain `':'`. The `signing-key:<name>` prefix is a reserved internal
   * namespace, so forbidding `':'` at creation time is what actually enforces
   * the documented guarantee that a secret and a signing key can never collide
   * under one name — the CLI's name pattern already forbids `':'`, and this
   * closes the same hole for direct library callers. Read/delete/existence
   * paths pass `false` so a legacy secret whose name contains `':'` (stored
   * before this rule, or seeded directly through a backend) stays reachable for
   * inspection and cleanup.
   */
  static #validateName(name: string, kind: 'secret' | 'signing key', enforceReserved = true): void {
    const noun = kind === 'secret' ? 'Secret' : 'Signing key'
    if (name.trim() === '') {
      throw new VaultError(`${noun} name must not be empty`)
    }
    if (enforceReserved && name.includes(':')) {
      throw new VaultError(
        `${noun} name must not contain ':'. The 'signing-key:' prefix is a reserved internal namespace, so a secret and a signing key can never collide under one name.`,
      )
    }
  }

  #resolveBackend(): SecretBackend {
    const enabledBackends = this.#config.backends.filter((b) => b.enabled)
    if (enabledBackends.length === 0) {
      throw new BackendUnavailableError(
        'No enabled backends configured',
        'none-enabled',
        this.#config.backends.map((b) => b.type),
      )
    }

    const firstEnabled = enabledBackends[0]
    if (firstEnabled === undefined) {
      throw new BackendUnavailableError('No enabled backends configured', 'none-enabled', [])
    }

    return BackendRegistry.create(firstEnabled.type, firstEnabled, this.#configDir)
  }

  /**
   * Resolve the backend-type hint used both for introspection
   * ({@link activeBackendType}) and for the `bkd` claim minted by
   * {@link setup}. A non-blank `override` wins (trimmed); an empty or
   * whitespace-only override is treated the same as no override, since
   * honoring it would mint a token with a blank `bkd` claim. Otherwise the
   * backend's declared `type` is used (trimmed), and a backend that declares
   * an empty or whitespace-only type — permitted for injected backends —
   * falls back to the stable `'custom'` sentinel. Centralizing this keeps
   * both paths in sync so no route ever mints a token with an empty `bkd`
   * claim (which {@link validateClaims} rejects, making the token unusable).
   */
  static #resolveBackendTypeHint(backend: SecretBackend, override?: string): string {
    const trimmedOverride = override?.trim()
    if (trimmedOverride !== undefined && trimmedOverride !== '') {
      return trimmedOverride
    }
    const declared = backend.type.trim()
    return declared === '' ? 'custom' : declared
  }

  #requireBackend(): SecretBackend {
    // Resolve the configured backend lazily on first use so that trust-only
    // operations never require a healthy/registered backend. #resolveBackend()
    // throws BackendUnavailableError if none is enabled or it cannot be built.
    this.#backend ??= this.#resolveBackend()
    return this.#backend
  }

  #isDevModeExecutable(executablePath: string): boolean {
    if (this.#config.developmentMode === undefined) {
      return false
    }
    return this.#config.developmentMode.executables.includes(executablePath)
  }

  /**
   * Resolve the executable identity to embed in a minted token, enforcing that
   * the caller made an explicit trust decision.
   *
   * Returns the sentinel `'dev'` (no executable binding) when trust is
   * deliberately skipped or the path is on the development-mode allowlist;
   * otherwise runs TOFU *verification only* and returns the verified hash
   * together with a `commit` callback. Verification never writes to the trust
   * manifest by itself — `commit` stages that write, and the caller
   * ({@link VaultKeeper.setup}) must invoke it only after the operation trust
   * was gating has actually succeeded. This is the fail-fast/defer-write split
   * from issue #148: shape validation (missing/conflicting/legacy-sentinel)
   * still throws immediately here, before any backend read, but a
   * first-encounter or Sigstore hash is not durably recorded until `commit`
   * runs.
   *
   * @throws {ExecutableTrustRequiredError} If neither `executablePath` nor
   *   `skipTrust: true` is provided, if both are, or if `executablePath` is the
   *   retired legacy `'dev'` opt-out sentinel.
   * @throws {IdentityMismatchError} On a TOFU hash conflict. Conflicts never
   *   stage a manifest write regardless of whether `commit` is later called.
   */
  async #resolveExecutableIdentity(
    options: TrustChoiceInput | undefined,
  ): Promise<{ exeIdentity: string; commit: () => Promise<void> }> {
    const executablePath = options?.executablePath
    const skipTrust = options?.skipTrust === true
    const noCommit = (): Promise<void> => Promise.resolve()

    if (skipTrust && executablePath !== undefined) {
      throw new ExecutableTrustRequiredError(
        'VaultKeeper.setup() received both options.executablePath and ' +
          'options.skipTrust: true, which are mutually exclusive. Pass ' +
          'options.executablePath to verify the calling executable, or ' +
          'options.skipTrust: true to skip verification (development only) — not both.',
        'conflicting-choice',
      )
    }

    if (skipTrust) {
      // Explicit, greppable development-only opt-out: no executable identity is
      // bound. See the security warning on SetupOptions.skipTrust.
      return { exeIdentity: 'dev', commit: noCommit }
    }

    if (executablePath === undefined) {
      throw new ExecutableTrustRequiredError(
        'VaultKeeper.setup() requires an explicit executable-trust choice and ' +
          'no longer defaults to skipping verification. Either pass ' +
          "options.executablePath set to the calling executable's real path " +
          '(runs trust-on-first-use verification), or set options.skipTrust: ' +
          'true to deliberately skip verification (development only).',
        'missing-choice',
      )
    }

    // Reject the retired legacy opt-out sentinel. Before explicit-trust,
    // options.executablePath: 'dev' was the documented way to skip verification;
    // it is no longer special and would otherwise be resolved as a real path
    // (<cwd>/dev), hashed, and fail with a confusing "cannot read executable"
    // FilesystemError. Point migrating callers at the dedicated opt-out instead.
    if (executablePath === 'dev') {
      throw new ExecutableTrustRequiredError(
        "VaultKeeper.setup() no longer supports the legacy options.executablePath: 'dev' " +
          'sentinel for skipping trust verification. Set options.skipTrust: true to ' +
          'deliberately skip verification (development only), or pass ' +
          "options.executablePath set to the calling executable's real path to verify it.",
        'legacy-dev-sentinel',
      )
    }

    // A real path may still be exempted via the established development-mode
    // allowlist (setDevelopmentMode); otherwise run full TOFU verification.
    if (this.#isDevModeExecutable(executablePath)) {
      return { exeIdentity: 'dev', commit: noCommit }
    }

    // Resolve to an absolute path before verification so the manifest is keyed
    // consistently with approveExecutable() and checkExecutableTrust(), both of
    // which resolve. A relative path approved earlier (stored under its absolute
    // key) therefore matches here too.
    //
    // verifyTrustPending only *verifies* — a first-encounter or Sigstore hash
    // is staged on the returned value, not written. Committing it is deferred
    // to the caller (see #148).
    const pending = await verifyTrustPending(path.resolve(executablePath), {
      configDir: this.#configDir,
    })
    if (pending.tofuConflict) {
      // On a conflict the manifest holds at least one prior approved hash;
      // report the most recently approved one as the previous hash. Nothing
      // was staged for this conflict (verifyTrustPending never stages a write
      // on tofuConflict), so there is nothing to avoid committing here.
      const previousHash = pending.approvedHashes.at(-1) ?? pending.identity.hash
      throw new IdentityMismatchError(
        'Executable hash changed — re-approval required',
        previousHash,
        pending.identity.hash,
      )
    }
    return { exeIdentity: pending.identity.hash, commit: () => commitTrust(pending) }
  }

  async #decryptWithKeyResolution(
    jwe: string,
    kid: string | undefined,
  ): Promise<{ claims: VaultClaims; keyStatus: 'current' | 'previous' }> {
    // Try to find key by kid
    if (kid !== undefined) {
      const key = this.#keyManager.findKeyById(kid)
      if (key !== undefined) {
        const claims = await decryptToken(key.key, jwe)
        const isCurrent = key.id === this.#keyManager.getCurrentKey().id
        return {
          claims,
          keyStatus: isCurrent ? 'current' : 'previous',
        }
      }
      // kid not found — key may have been revoked
      throw new KeyRevokedError(`Key ${kid} not found — may have been revoked`)
    }

    // No kid — try current key first, then previous
    try {
      const claims = await decryptToken(this.#keyManager.getCurrentKey().key, jwe)
      return { claims, keyStatus: 'current' }
    } catch {
      const previousKey = this.#keyManager.getPreviousKey()
      if (previousKey !== undefined) {
        const claims = await decryptToken(previousKey.key, jwe)
        return { claims, keyStatus: 'previous' }
      }
      throw new VaultError('Failed to decrypt JWE with any available key')
    }
  }
}
