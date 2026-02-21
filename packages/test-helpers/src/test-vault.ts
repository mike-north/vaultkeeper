/**
 * Pre-configured VaultKeeper for consumer tests.
 */

import type { VaultConfig } from 'vaultkeeper'
import { VaultKeeper, BackendRegistry } from 'vaultkeeper'
import { InMemoryBackend } from './in-memory-backend.js'

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
 * await vault.backend.store('my-secret', 'hunter2')
 * const jwe = await vault.keeper.setup('my-secret')
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
   * Reset the test vault by clearing all stored secrets.
   * @public
   */
  reset(): void {
    this.backend.clear()
  }
}
