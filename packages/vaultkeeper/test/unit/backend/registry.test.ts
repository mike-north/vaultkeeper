import { describe, it, expect, beforeEach } from 'vitest'
import { BackendRegistry } from '../../../src/backend/registry.js'
import { BackendUnavailableError } from '../../../src/errors.js'
import type { SecretBackend } from '../../../src/backend/types.js'

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
    // Clear registry state between tests by re-assigning via a fresh approach.
    // Since the registry is a static class we test in isolation.
    // Reset by registering fresh types only — we cannot clear the map directly.
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
