/**
 * VaultKeeper main class — wires together all vaultkeeper subsystems.
 */

import * as crypto from 'node:crypto'
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
import { BackendRegistry } from './backend/registry.js'
import type { SecretBackend } from './backend/types.js'
import { createToken, decryptToken, extractKid, validateClaims, blockToken } from './jwe/index.js'
import { verifyTrust } from './identity/trust.js'
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
import {
  IdentityMismatchError,
  BackendUnavailableError,
  VaultError,
  KeyRevokedError,
} from './errors.js'

/** Options for initializing VaultKeeper. */
export interface VaultKeeperOptions {
  /** Override the config directory. */
  configDir?: string | undefined
  /** Supply config directly, skipping file load. */
  config?: VaultConfig | undefined
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

/** Usage tracking for tokens with use limits. */
const usageCounts = new Map<string, number>()

/**
 * Main entry point for vaultkeeper. Orchestrates backends, keys, JWE tokens,
 * identity verification, and access patterns.
 */
export class VaultKeeper {
  readonly #config: VaultConfig
  readonly #keyManager: KeyManager
  readonly #configDir: string
  #backend: SecretBackend | undefined

  private constructor(config: VaultConfig, keyManager: KeyManager, configDir: string) {
    this.#config = config
    this.#keyManager = keyManager
    this.#configDir = configDir
  }

  /**
   * Initialize a new VaultKeeper instance.
   * Runs doctor checks (unless skipped), loads config, and sets up the key manager.
   */
  static async init(options?: VaultKeeperOptions): Promise<VaultKeeper> {
    if (options?.skipDoctor !== true) {
      const doctorResult = await runDoctor()
      if (!doctorResult.ready) {
        throw new VaultError(
          `System not ready: ${doctorResult.nextSteps.join('; ')}`,
        )
      }
    }

    const configDir = options?.configDir ?? getDefaultConfigDir()
    const config = options?.config ?? (await loadConfig(configDir))

    const keyManager = new KeyManager()
    await keyManager.init()

    const vault = new VaultKeeper(config, keyManager, configDir)
    vault.#backend = vault.#resolveBackend()

    return vault
  }

  /** Run doctor checks without full initialization. */
  static async doctor(): Promise<PreflightResult> {
    return runDoctor()
  }

  /**
   * Store a secret and return a JWE token that encapsulates it.
   *
   * @param secretName - Identifier for the secret
   * @param options - Setup options
   * @returns Compact JWE string
   */
  async setup(secretName: string, options?: SetupOptions): Promise<string> {
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
      const trustResult = await verifyTrust(executablePath, {
        configDir: this.#configDir,
      })
      if (trustResult.tofuConflict) {
        throw new IdentityMismatchError(
          'Executable hash changed — re-approval required',
          'previously-approved',
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
   * @returns Opaque capability token for use with fetch/exec/getSecret
   */
  async authorize(jwe: string): Promise<{ token: CapabilityToken; response: VaultResponse }> {
    const kid = extractKid(jwe)
    const { claims, keyStatus } = await this.#decryptWithKeyResolution(jwe, kid)

    // Validate claims (expiry, blocklist, usage)
    const jti = claims.jti
    const currentCount = usageCounts.get(jti) ?? 0
    validateClaims(claims, currentCount)

    // Track usage and evict finished tokens to prevent unbounded map growth.
    const newCount = currentCount + 1
    if (claims.use !== null && newCount >= claims.use) {
      // Token has reached its usage limit — remove from tracking and block it
      // so future attempts hit the blocklist rather than the usageCounts map.
      usageCounts.delete(jti)
      blockToken(jti)
    } else {
      usageCounts.set(jti, newCount)
    }

    const token = createCapabilityToken(claims)

    const response: VaultResponse = { keyStatus }
    if (keyStatus === 'previous') {
      // Re-encrypt with current key
      const currentKey = this.#keyManager.getCurrentKey()
      const rotatedJwt = await createToken(currentKey.key, claims, { kid: currentKey.id })
      response.rotatedJwt = rotatedJwt
    }

    return { token, response }
  }

  /**
   * Execute a delegated HTTP fetch, injecting the secret from the token.
   *
   * The secret value is substituted for every `{{secret}}` placeholder found
   * in `request.url`, `request.headers`, and `request.body` before the fetch
   * is executed. The raw secret is never exposed in the return value.
   *
   * @param token - A `CapabilityToken` obtained from `authorize()`.
   * @param request - The fetch request template. Use `{{secret}}` as a
   *   placeholder wherever the secret value should be injected.
   * @returns The `Response` from the underlying `fetch()` call, together with
   *   the vault metadata (`vaultResponse`).
   * @throws {Error} If `token` is invalid or was not created by this vault
   *   instance.
   */
  async fetch(
    token: CapabilityToken,
    request: FetchRequest,
  ): Promise<{ response: Response; vaultResponse: VaultResponse }> {
    const claims = validateCapabilityToken(token)
    const response = await delegatedFetch(claims.val, request)
    return {
      response,
      vaultResponse: { keyStatus: 'current' },
    }
  }

  /**
   * Execute a delegated command, injecting the secret from the token.
   *
   * The secret value is substituted for every `{{secret}}` placeholder found
   * in `request.args` and `request.env` values before the process is spawned.
   * The raw secret is never exposed in the return value.
   *
   * @param token - A `CapabilityToken` obtained from `authorize()`.
   * @param request - The exec request template. Use `{{secret}}` as a
   *   placeholder wherever the secret value should be injected.
   * @returns The command result (`stdout`, `stderr`, `exitCode`) together with
   *   the vault metadata (`vaultResponse`).
   * @throws {Error} If `token` is invalid or was not created by this vault
   *   instance.
   */
  async exec(
    token: CapabilityToken,
    request: ExecRequest,
  ): Promise<{ result: ExecResult; vaultResponse: VaultResponse }> {
    const claims = validateCapabilityToken(token)
    const result = await delegatedExec(claims.val, request)
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
    this.#keyManager.rotateKey(gracePeriodMs)
    await Promise.resolve()
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
    await Promise.resolve()
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

  // ---------------------------------------------------------------------------
  // Private helpers
  // ---------------------------------------------------------------------------

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
      throw new BackendUnavailableError(
        'No enabled backends configured',
        'none-enabled',
        [],
      )
    }

    return BackendRegistry.create(firstEnabled.type)
  }

  #requireBackend(): SecretBackend {
    if (this.#backend === undefined) {
      throw new VaultError('VaultKeeper backend not initialized')
    }
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
