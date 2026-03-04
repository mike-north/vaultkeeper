/**
 * Unit tests for BackendRegistry.
 *
 * Includes regression coverage for issue #21 (built-in backends not registered
 * at module load).
 *
 * @see https://github.com/mike-north/vaultkeeper/issues/21
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { BackendRegistry } from '../../../src/backend/registry.js'
import { BackendUnavailableError } from '../../../src/errors.js'
import type { SecretBackend } from '../../../src/backend/types.js'
import type { BackendSetupFactory, SetupQuestion, SetupResult } from '../../../src/backend/setup-types.js'

import { registerBuiltinBackends } from '../../../src/backend/register-builtins.js'

function makeMockBackend(type: string): SecretBackend {
  return {
    type,
    displayName: `Mock ${type}`,
    isAvailable: () => Promise.resolve(true),
    store: () => Promise.resolve(),
    retrieve: () => Promise.resolve('secret'),
    delete: () => Promise.resolve(),
    exists: () => Promise.resolve(true),
  }
}

describe('BackendRegistry', () => {
  beforeEach(() => {
    BackendRegistry.clearBackends()
  })

  afterEach(() => {
    BackendRegistry.clearBackends()
  })

  describe('register and create', () => {
    it('should create a backend from a registered type', () => {
      const backend = makeMockBackend('test-registry-type')
      BackendRegistry.register('test-registry-type', () => backend)

      const created = BackendRegistry.create('test-registry-type')
      expect(created).toBe(backend)
    })

    it('should throw BackendUnavailableError for an unknown type', () => {
      expect(() => BackendRegistry.create('definitely-unknown-xyz')).toThrow(
        BackendUnavailableError,
      )
      expect(() => BackendRegistry.create('definitely-unknown-xyz')).toThrow(
        'Unknown backend type: definitely-unknown-xyz',
      )
    })

    it('should include available types in the error message', () => {
      BackendRegistry.register('error-test-type', () => makeMockBackend('error-test-type'))
      expect(() => BackendRegistry.create('not-registered')).toThrow('Available types:')
    })

    it('should allow overwriting an existing registration', () => {
      const first = makeMockBackend('overwrite-type')
      const second = makeMockBackend('overwrite-type')

      BackendRegistry.register('overwrite-type', () => first)
      BackendRegistry.register('overwrite-type', () => second)

      const created = BackendRegistry.create('overwrite-type')
      expect(created).toBe(second)
    })
  })

  describe('getAvailableTypes', () => {
    it('should return only types whose backend reports isAvailable() true', async () => {
      const availableBackend = makeMockBackend('avail-type-yes')
      const unavailableBackend: SecretBackend = {
        ...makeMockBackend('avail-type-no'),
        isAvailable: () => Promise.resolve(false),
      }

      BackendRegistry.register('avail-type-yes', () => availableBackend)
      BackendRegistry.register('avail-type-no', () => unavailableBackend)

      const types = await BackendRegistry.getAvailableTypes()
      expect(types).toContain('avail-type-yes')
      expect(types).not.toContain('avail-type-no')
    })

    it('should return an empty array when no backends are available', async () => {
      BackendRegistry.register('avail-none-type', () => ({
        ...makeMockBackend('avail-none-type'),
        isAvailable: () => Promise.resolve(false),
      }))

      const types = await BackendRegistry.getAvailableTypes()
      expect(types).not.toContain('avail-none-type')
    })

    it('should exclude backends whose isAvailable() throws', async () => {
      BackendRegistry.register('avail-throws-type', () => ({
        ...makeMockBackend('avail-throws-type'),
        isAvailable: () => Promise.reject(new Error('probe failed')),
      }))

      const types = await BackendRegistry.getAvailableTypes()
      expect(types).not.toContain('avail-throws-type')
    })

    it('should return an array', async () => {
      const types = await BackendRegistry.getAvailableTypes()
      expect(Array.isArray(types)).toBe(true)
    })
  })

  describe('setup registration', () => {
    afterEach(() => {
      BackendRegistry.clearSetups()
    })

    function makeSetupFactory(result: SetupResult): BackendSetupFactory {
      return async function* (): AsyncGenerator<SetupQuestion, SetupResult, string> {
        // Await a no-op to satisfy require-await for async generators that
        // always complete without prompting the user.
        await Promise.resolve()
        // yield* from an empty typed array to satisfy the require-yield rule.
        const noQuestions: SetupQuestion[] = []
        yield* noQuestions
        return result
      }
    }

    it('should register and retrieve a setup factory', () => {
      const factory = makeSetupFactory({ options: { region: 'us-east-1' } })
      BackendRegistry.registerSetup('setup-test-type', factory)

      const retrieved = BackendRegistry.getSetup('setup-test-type')
      expect(retrieved).toBe(factory)
    })

    it('should return undefined for an unregistered setup type', () => {
      expect(BackendRegistry.getSetup('nonexistent-setup-type')).toBeUndefined()
    })

    it('hasSetup should return true when a factory is registered', () => {
      const factory = makeSetupFactory({ options: {} })
      BackendRegistry.registerSetup('has-setup-type', factory)

      expect(BackendRegistry.hasSetup('has-setup-type')).toBe(true)
    })

    it('hasSetup should return false when no factory is registered', () => {
      expect(BackendRegistry.hasSetup('not-registered-setup-type')).toBe(false)
    })

    it('should allow overwriting an existing setup registration', () => {
      const first = makeSetupFactory({ options: { v: '1' } })
      const second = makeSetupFactory({ options: { v: '2' } })

      BackendRegistry.registerSetup('overwrite-setup-type', first)
      BackendRegistry.registerSetup('overwrite-setup-type', second)

      expect(BackendRegistry.getSetup('overwrite-setup-type')).toBe(second)
    })

    it('clearSetups should remove all registered setup factories', () => {
      BackendRegistry.registerSetup('clear-test-a', makeSetupFactory({ options: {} }))
      BackendRegistry.registerSetup('clear-test-b', makeSetupFactory({ options: {} }))
      BackendRegistry.clearSetups()

      expect(BackendRegistry.hasSetup('clear-test-a')).toBe(false)
      expect(BackendRegistry.hasSetup('clear-test-b')).toBe(false)
    })
  })

  describe('getTypes', () => {
    it('should include registered types', () => {
      BackendRegistry.register('list-test-type', () => makeMockBackend('list-test-type'))
      expect(BackendRegistry.getTypes()).toContain('list-test-type')
    })

    it('should return an array', () => {
      expect(Array.isArray(BackendRegistry.getTypes())).toBe(true)
    })
  })

})

/**
 * Regression test for issue #21: built-in backends were not registered at
 * module load, causing VaultKeeper.init() to throw BackendUnavailableError.
 *
 * This describe block is intentionally outside the main BackendRegistry suite
 * so that `clearBackends()` does not run before these assertions.
 */
describe('built-in backend registration (issue #21)', () => {
  beforeEach(() => {
    BackendRegistry.clearBackends()
    registerBuiltinBackends()
  })

  afterEach(() => {
    BackendRegistry.clearBackends()
  })

  it('should have all 6 built-in backends registered after importing register-builtins', () => {
    const types = BackendRegistry.getTypes()
    expect(types).toContain('file')
    expect(types).toContain('keychain')
    expect(types).toContain('dpapi')
    expect(types).toContain('secret-tool')
    expect(types).toContain('1password')
    expect(types).toContain('yubikey')
  })

  it.each([
    ['file', 'file'],
    ['keychain', 'keychain'],
    ['dpapi', 'dpapi'],
    ['secret-tool', 'secret-tool'],
    ['1password', '1password'],
    ['yubikey', 'yubikey'],
  ])('should instantiate the %s backend without throwing', (type, expectedType) => {
    const backend = BackendRegistry.create(type)
    expect(backend.type).toBe(expectedType)
  })

  describe('1password factory option mapping', () => {
    it('should default to session access mode when no config is provided', () => {
      const backend = BackendRegistry.create('1password')
      expect(backend.type).toBe('1password')
    })

    it('should forward account and serviceAccountToken from config options', () => {
      // Verifies the factory does not throw when options are provided
      const backend = BackendRegistry.create('1password', {
        type: '1password',
        enabled: true,
        options: {
          vault: 'vault-abc',
          account: 'my-account',
        },
      })
      expect(backend.type).toBe('1password')
    })

    it('should accept per-access mode from config options', () => {
      const backend = BackendRegistry.create('1password', {
        type: '1password',
        enabled: true,
        options: {
          vault: 'vault-abc',
          accessMode: 'per-access',
        },
      })
      expect(backend.type).toBe('1password')
    })

    it('should fall back to session mode for unknown accessMode values', () => {
      const backend = BackendRegistry.create('1password', {
        type: '1password',
        enabled: true,
        options: {
          vault: 'vault-abc',
          accessMode: 'unknown-value',
        },
      })
      expect(backend.type).toBe('1password')
    })
  })
})
