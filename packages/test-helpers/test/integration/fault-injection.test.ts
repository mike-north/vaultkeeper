import { describe, it, expect, beforeEach } from 'vitest'
import { InMemoryBackend } from '../../src/index.js'
import {
  BackendUnavailableError,
  SecretNotFoundError,
  SigningKeyNotFoundError,
  AuthorizationDeniedError,
  BackendLockedError,
} from 'vaultkeeper'

// Acceptance criterion 3: one-shot fault fires once then clears; persistent
// fault fires until explicitly removed. Exercised directly against the real
// InMemoryBackend (real in-memory state, not a hand-built approximation).
describe('InMemoryBackend fault injection', () => {
  let backend: InMemoryBackend

  beforeEach(() => {
    backend = new InMemoryBackend()
  })

  describe('one-shot mode (default)', () => {
    it('fires exactly once, then the next identical call succeeds', async () => {
      backend.injectFault('store', 'backend-unavailable')

      await expect(backend.store('k', 'v')).rejects.toBeInstanceOf(BackendUnavailableError)
      // The fault has cleared itself — this call must succeed.
      await expect(backend.store('k', 'v')).resolves.toBeUndefined()
      expect(await backend.retrieve('k')).toBe('v')
    })

    it('is scoped to a single operation and does not leak to others', async () => {
      backend.injectFault('retrieve', 'backend-unavailable')
      // store is unaffected by a fault armed only for retrieve.
      await expect(backend.store('k', 'v')).resolves.toBeUndefined()
      await expect(backend.retrieve('k')).rejects.toBeInstanceOf(BackendUnavailableError)
    })
  })

  describe('persistent mode', () => {
    it('fires on every matching call until explicitly cleared', async () => {
      backend.injectFault('store', 'permission-denied', { persistent: true })

      await expect(backend.store('k', 'v')).rejects.toBeInstanceOf(AuthorizationDeniedError)
      await expect(backend.store('k', 'v')).rejects.toBeInstanceOf(AuthorizationDeniedError)
      await expect(backend.store('k', 'v')).rejects.toBeInstanceOf(AuthorizationDeniedError)

      backend.clearFault('store')
      await expect(backend.store('k', 'v')).resolves.toBeUndefined()
    })

    it('clearAllFaults removes every armed fault regardless of mode', async () => {
      backend.injectFault('store', 'permission-denied', { persistent: true })
      backend.injectFault('retrieve', 'session-expired', { persistent: true })

      backend.clearAllFaults()

      await expect(backend.store('k', 'v')).resolves.toBeUndefined()
      await expect(backend.retrieve('k')).resolves.toBe('v')
    })
  })

  describe('mode -> typed error mapping', () => {
    it('backend-unavailable -> BackendUnavailableError', async () => {
      backend.injectFault('store', 'backend-unavailable')
      await expect(backend.store('k', 'v')).rejects.toBeInstanceOf(BackendUnavailableError)
    })

    it('key-absent on a plain secret operation -> SecretNotFoundError', async () => {
      await backend.store('k', 'v')
      backend.injectFault('retrieve', 'key-absent')
      await expect(backend.retrieve('k')).rejects.toBeInstanceOf(SecretNotFoundError)
    })

    it('key-absent on a signing operation -> SigningKeyNotFoundError', async () => {
      await backend.generateSigningKey('sk', 'EdDSA')
      backend.injectFault('getPublicKey', 'key-absent')
      await expect(backend.getPublicKey('sk')).rejects.toBeInstanceOf(SigningKeyNotFoundError)
    })

    it('permission-denied -> AuthorizationDeniedError', async () => {
      backend.injectFault('delete', 'permission-denied')
      await expect(backend.delete('k')).rejects.toBeInstanceOf(AuthorizationDeniedError)
    })

    it('session-expired -> BackendLockedError', async () => {
      backend.injectFault('exists', 'session-expired')
      await expect(backend.exists('k')).rejects.toBeInstanceOf(BackendLockedError)
    })
  })
})
