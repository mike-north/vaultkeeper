/**
 * Pre-configured VaultKeeper for consumer tests.
 */

import type { Buffer } from 'node:buffer'
import type { VaultConfig, SetupOptionsBase, SigningAlgorithm, SigningPublicKey } from 'vaultkeeper'
import { VaultKeeper, BackendRegistry } from 'vaultkeeper'
import { InMemoryBackend } from './in-memory-backend.js'

/**
 * Result of {@link TestVault.signCeremony}: the detached-payload compact JWS
 * produced by the ceremony's final `sign()` step, alongside the public key
 * exported from its `createSigningKey()` step (for offline verification via
 * `VaultKeeper.verify`).
 * @public
 */
export interface TestVaultSignCeremonyResult {
  /** The detached-payload compact JWS (`<protected>..<signature>`). */
  jws: string
  /** The public half of the signing key the ceremony enrolled. */
  publicKey: SigningPublicKey
}

/**
 * Options accepted by {@link TestVault.setup}. Deliberately looser than the
 * library's discriminated `SetupOptions` union: the trust choice is optional
 * here because `TestVault.setup` defaults it to `skipTrust: true` when omitted,
 * so tests can call `setup('NAME')` with no trust choice at all.
 *
 * @public
 */
export interface TestVaultSetupOptions extends SetupOptionsBase {
  /** Bind the token to this executable path (real TOFU verification). */
  executablePath?: string | undefined
  /** Skip verification. Omitting a trust choice defaults to `true`. */
  skipTrust?: boolean | undefined
}

/** Default test configuration with short TTL and dev-mode trust. */
const TEST_CONFIG: VaultConfig = {
  version: 1,
  backends: [{ type: 'memory', enabled: true }],
  keyRotation: { gracePeriodDays: 1 },
  defaults: { ttlMinutes: 5, trustTier: 1 },
  developmentMode: { executables: ['dev'] },
}

/**
 * Options for creating a {@link TestVault}.
 * @public
 */
export interface TestVaultOptions {
  /** Override the default TTL in minutes. */
  ttlMinutes?: number | undefined
  /** Override the default trust tier. */
  trustTier?: 1 | 2 | 3 | undefined
}

/**
 * A pre-configured vault for consumer test workflows.
 *
 * @remarks
 * `TestVault` wraps a real `VaultKeeper` instance backed by an
 * {@link InMemoryBackend}. It skips doctor checks and uses dev-mode
 * identity, making it suitable for fast, hermetic tests.
 *
 * @example
 * ```ts
 * const vault = await TestVault.create()
 * await vault.store('my-secret', 'hunter2')
 * const jwe = await vault.setup('my-secret')
 * const { token } = await vault.keeper.authorize(jwe)
 * ```
 *
 * @public
 */
export class TestVault {
  /** The underlying VaultKeeper instance. */
  readonly keeper: VaultKeeper

  /** The in-memory backend used by this test vault. */
  readonly backend: InMemoryBackend

  private constructor(keeper: VaultKeeper, backend: InMemoryBackend) {
    this.keeper = keeper
    this.backend = backend
  }

  /**
   * Create a new TestVault, ready for use.
   *
   * @param options - Optional overrides for TTL and trust tier.
   * @returns A fully-initialized TestVault.
   *
   * @public
   */
  static async create(options?: TestVaultOptions): Promise<TestVault> {
    const backend = new InMemoryBackend()

    // Register the in-memory backend so VaultKeeper can resolve it
    BackendRegistry.register('memory', () => backend)

    const config: VaultConfig = {
      ...TEST_CONFIG,
      defaults: {
        ttlMinutes: options?.ttlMinutes ?? TEST_CONFIG.defaults.ttlMinutes,
        trustTier: options?.trustTier ?? TEST_CONFIG.defaults.trustTier,
      },
    }

    const keeper = await VaultKeeper.init({
      skipDoctor: true,
      config,
    })

    return new TestVault(keeper, backend)
  }

  /**
   * Store a secret in the test backend.
   *
   * @remarks
   * Convenience shorthand for `vault.backend.store(name, value)`.
   *
   * @param name - The secret identifier.
   * @param value - The secret value.
   * @returns A promise that resolves when the secret has been written.
   * @public
   */
  store(name: string, value: string): Promise<void> {
    return this.backend.store(name, value)
  }

  /**
   * Mint a JWE for a stored secret via the wrapped keeper.
   *
   * @remarks
   * Convenience shorthand for `vault.keeper.setup(name, options)` that defaults
   * to the development-only `skipTrust: true` opt-out, so tests stay hermetic
   * (there is no real calling executable to hash). Pass `executablePath`
   * explicitly to exercise real TOFU verification instead. Mirroring
   * `VaultKeeper`'s own semantics, only `executablePath` or `skipTrust: true`
   * count as an explicit trust choice — `skipTrust: false` is not a choice, so
   * it is treated the same as omitting the option entirely and still receives
   * the convenience default. If `executablePath` is supplied it always wins (it
   * cannot be combined with `skipTrust` — the library's `SetupOptions` union
   * forbids both).
   *
   * @param name - The secret identifier.
   * @param options - Optional setup options; the trust choice defaults to
   *   `skipTrust: true` when the caller does not specify one.
   * @returns The minted compact JWE string.
   * @public
   */
  setup(name: string, options?: TestVaultSetupOptions): Promise<string> {
    // Split the loose test-facing options into base fields and the trust choice,
    // then hand the wrapped keeper a value that satisfies its strict
    // discriminated `SetupOptions` union. Only `executablePath` or an explicit
    // `skipTrust: true` counts as a trust choice; anything else (including
    // `skipTrust: false`) falls back to the hermetic `skipTrust: true` default.
    const { executablePath, skipTrust: _skipTrust, ...base } = options ?? {}
    if (executablePath !== undefined) {
      return this.keeper.setup(name, { ...base, executablePath })
    }
    return this.keeper.setup(name, { ...base, skipTrust: true })
  }

  /**
   * Delete a secret from the test backend.
   *
   * @remarks
   * Convenience shorthand for `vault.backend.delete(name)`. Resolves without
   * error if the secret does not exist.
   *
   * @param name - The secret identifier.
   * @returns A promise that resolves when the secret has been removed.
   * @public
   */
  delete(name: string): Promise<void> {
    return this.backend.delete(name)
  }

  /**
   * Reset the test vault by clearing all stored secrets, signing keys, and
   * any armed faults on the underlying backend.
   *
   * @remarks
   * Delegates to `InMemoryBackend.clear()`, so a fault left armed (especially
   * a persistent one) from a prior test case cannot leak into the next.
   *
   * @public
   */
  reset(): void {
    this.backend.clear()
  }

  /**
   * Run the full production signing ceremony — `createSigningKey` →
   * `authorizeSigningKey` → `sign` — through the wrapped keeper in one call.
   *
   * @remarks
   * This exercises the exact same call path a real consumer uses to sign with
   * a vaultkeeper-managed key, so a test asserting on the returned `jws` is
   * exercising production wiring, not an approximation of it. The private key
   * never leaves the backend at any point in the ceremony (see
   * `VaultKeeper.createSigningKey` in the `vaultkeeper` package).
   *
   * @param name - Signing key name to enroll. Must not already exist and must
   *   not contain `':'`.
   * @param payload - The payload to sign. Strings are treated as UTF-8.
   * @param algorithm - The JOSE signing algorithm. Defaults to `'EdDSA'`, the
   *   only algorithm `InMemoryBackend` currently supports.
   * @returns The detached compact JWS and the enrolled public key.
   * @throws {SigningKeyAlreadyExistsError} If a signing key already exists
   *   under `name`.
   * @public
   */
  async signCeremony(
    name: string,
    payload: string | Buffer,
    algorithm: SigningAlgorithm = 'EdDSA',
  ): Promise<TestVaultSignCeremonyResult> {
    const publicKey = await this.keeper.createSigningKey(name, algorithm)
    const token = await this.keeper.authorizeSigningKey(name)
    const { result } = await this.keeper.sign(token, { payload })
    return { jws: result.jws, publicKey }
  }
}
