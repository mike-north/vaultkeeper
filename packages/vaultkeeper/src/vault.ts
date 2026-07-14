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
} from './types.js'
import { loadConfig, getDefaultConfigDir } from './config.js'
import { KeyManager } from './keys/manager.js'
import { loadKeyState, saveKeyState } from './keys/storage.js'
import { BackendRegistry } from './backend/registry.js'
import type { SecretBackend } from './backend/types.js'
import { createToken, decryptToken, extractKid, validateClaims, blockToken } from './jwe/index.js'
import { verifyTrust } from './identity/trust.js'
import { hashExecutable } from './identity/hash.js'
import { loadManifest, saveManifest, addTrustedHash, isTrusted } from './identity/manifest.js'
import {
  CapabilityToken,
  createCapabilityToken,
  validateCapabilityToken,
} from './identity/session.js'
import { delegatedFetch } from './access/delegated-fetch.js'
import { delegatedExec } from './access/delegated-exec.js'
import { createSecretAccessor } from './access/controlled-direct.js'
import { delegatedSign } from './access/delegated-sign.js'
import { delegatedVerify } from './access/delegated-verify.js'
import { runDoctor } from './doctor/runner.js'
import type { RunDoctorOptions } from './doctor/runner.js'
import {
  AuthorizationDeniedError,
  IdentityMismatchError,
  BackendUnavailableError,
  VaultError,
  KeyRevokedError,
  FilesystemError,
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
 * {@link VaultKeeperOptions.backend} is not set, the active backend falls
 * back to the platform default resolved by {@link platformDefaultBackendType}
 * — `keychain` on macOS, `dpapi` on Windows, `file` elsewhere. Inspect
 * {@link VaultKeeper.activeBackendType} after `init()` to confirm which
 * backend a given instance resolved to. When `backend` is set instead, see
 * that option's own JSDoc for the fallback config used in its place.
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

/** Options for the setup operation. */
export interface SetupOptions {
  /** TTL in minutes for the JWE. */
  ttlMinutes?: number | undefined
  /** Usage limit (null for unlimited). */
  useLimit?: number | null | undefined
  /** Executable path for identity binding. Use "dev" for dev mode. */
  executablePath?: string | undefined
  /** Trust tier override. */
  trustTier?: TrustTier | undefined
  /** Backend type to use. */
  backendType?: string | undefined
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
   * Use it to confirm which backend an instance resolved to, especially when
   * no config file exists and the platform default applies (see
   * {@link platformDefaultBackendType}). On macOS this reads `keychain` by
   * default, meaning secret operations target the real OS Keychain.
   *
   * @throws A {@link BackendUnavailableError} only when the configuration has
   * no enabled backend at all (a configuration error, not a backend fault).
   *
   * @public
   */
  get activeBackendType(): string {
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
   * Store a secret in the configured backend.
   *
   * This is a convenience method that delegates to the active backend's
   * `store()` method. If a secret with the same name already exists, it is
   * overwritten.
   *
   * @param name - Identifier for the secret.
   * @param value - The secret value to store.
   * @public
   */
  async store(name: string, value: string): Promise<void> {
    VaultKeeper.#validateSecretName(name)
    const backend = this.#requireBackend()
    await backend.store(name, value)
  }

  /**
   * Delete a secret from the configured backend.
   *
   * This is a convenience method that delegates to the active backend's
   * `delete()` method.
   *
   * @param name - Identifier for the secret to delete.
   * @public
   */
  async delete(name: string): Promise<void> {
    VaultKeeper.#validateSecretName(name)
    const backend = this.#requireBackend()
    await backend.delete(name)
  }

  /**
   * Read a stored secret from the backend and mint a JWE token that encapsulates it.
   *
   * @param secretName - Identifier for the secret
   * @param options - Setup options
   * @returns Compact JWE string
   */
  async setup(secretName: string, options?: SetupOptions): Promise<string> {
    VaultKeeper.#validateSecretName(secretName)
    const backend = this.#requireBackend()
    const backendType = options?.backendType ?? backend.type
    const ttlMinutes = options?.ttlMinutes ?? this.#config.defaults.ttlMinutes
    const trustTier = options?.trustTier ?? this.#config.defaults.trustTier
    const useLimit = options?.useLimit ?? null
    const executablePath = options?.executablePath ?? 'dev'

    const secretValue = await backend.retrieve(secretName)

    let exeIdentity: string
    if (executablePath === 'dev' || this.#isDevModeExecutable(executablePath)) {
      exeIdentity = 'dev'
    } else {
      // Resolve to an absolute path before verification so the manifest is
      // keyed consistently with approveExecutable() and checkExecutableTrust(),
      // both of which resolve. A relative path approved earlier (stored under
      // its absolute key) therefore matches here too.
      const trustResult = await verifyTrust(path.resolve(executablePath), {
        configDir: this.#configDir,
      })
      if (trustResult.tofuConflict) {
        // On a conflict the manifest holds at least one prior approved hash;
        // report the most recently approved one as the previous hash.
        const previousHash = trustResult.approvedHashes.at(-1) ?? trustResult.identity.hash
        throw new IdentityMismatchError(
          'Executable hash changed — re-approval required',
          previousHash,
          trustResult.identity.hash,
        )
      }
      exeIdentity = trustResult.identity.hash
    }

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
    return createToken(currentKey.key, claims, { kid: currentKey.id })
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
   * The raw secret is never exposed in the return value.
   *
   * @param token - A single `CapabilityToken` or a `SecretTokenMap` mapping
   *   names to tokens obtained from `authorize()`.
   * @param request - The exec request template with placeholders.
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
   * @throws {Error} If `token` is invalid or was not created by this vault
   *   instance.
   */
  getSecret(token: CapabilityToken): SecretAccessor {
    const claims = validateCapabilityToken(token)
    return createSecretAccessor(claims.val)
  }

  /**
   * Sign data using the private key embedded in a capability token.
   *
   * The signing key is extracted from the token's encrypted claims, used
   * for a single `crypto.sign()` call, and never exposed to the caller.
   * The algorithm is auto-detected from the key type unless overridden
   * in the request.
   *
   * @param token - A `CapabilityToken` obtained from `authorize()`.
   * @param request - The data to sign and optional algorithm override.
   * @returns The base64-encoded signature and algorithm label, together
   *   with the vault metadata (`vaultResponse`).
   * @throws {VaultError} If `token` is invalid or was not created by this
   *   vault instance.
   * @throws {InvalidAlgorithmError} If `request.algorithm` is not in the
   *   allowed set (e.g. `'md5'`).
   * @throws {InvalidKeyMaterialError} If the stored secret is not valid
   *   PEM/DER private key material.
   */
  async sign(
    token: CapabilityToken,
    request: SignRequest,
  ): Promise<{ result: SignResult; vaultResponse: VaultResponse }> {
    const claims = validateCapabilityToken(token)
    const result = delegatedSign(claims.val, request)
    // Await to satisfy require-await; sign() is async for API consistency
    // with fetch()/exec() and to reserve the right to check vaultResponse.rotatedJwt.
    await Promise.resolve()
    return {
      result,
      vaultResponse: { keyStatus: 'current' },
    }
  }

  /**
   * Verify a signature using a public key.
   *
   * This is a static method — no VaultKeeper instance, secrets, or
   * capability tokens are required. It is safe to call from CI or any
   * context that has access to public key material.
   *
   * Returns `false` for invalid key material, malformed signatures, or
   * any verification failure (except disallowed algorithms, which throw).
   *
   * @throws {InvalidAlgorithmError} If `request.algorithm` is not in the
   *   allowed set (e.g. `'md5'`).
   *
   * @param request - The data, signature, public key, and optional
   *   algorithm override.
   * @returns `true` if the signature is valid, `false` otherwise.
   */
  static verify(request: VerifyRequest): boolean {
    return delegatedVerify(request)
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
    const hash = await VaultKeeper.#hashExecutableOrThrow(resolved)
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
    const hash = await VaultKeeper.#hashExecutableOrThrow(resolved)
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

  /**
   * Hash the file at `resolvedPath`, converting any read failure (e.g. a
   * missing file) into a typed {@link FilesystemError} that names the path.
   */
  static async #hashExecutableOrThrow(resolvedPath: string): Promise<string> {
    try {
      return await hashExecutable(resolvedPath)
    } catch (err) {
      const detail = err instanceof Error ? err.message : String(err)
      throw new FilesystemError(
        `Cannot read executable at ${resolvedPath}: ${detail}`,
        resolvedPath,
        'read',
      )
    }
  }

  static #resolveSecrets(token: CapabilityToken | SecretTokenMap): string | Record<string, string> {
    if (token instanceof CapabilityToken) {
      return validateCapabilityToken(token).val
    }
    const result: Record<string, string> = {}
    for (const [name, t] of Object.entries(token)) {
      if (!(t instanceof CapabilityToken)) {
        throw new AuthorizationDeniedError(
          `Invalid capability token for secret "${name}" — expected a CapabilityToken from authorize()`,
        )
      }
      result[name] = validateCapabilityToken(t).val
    }
    return result
  }

  static #validateSecretName(name: string): void {
    if (name.trim() === '') {
      throw new VaultError('Secret name must not be empty')
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

    return BackendRegistry.create(firstEnabled.type, firstEnabled)
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
