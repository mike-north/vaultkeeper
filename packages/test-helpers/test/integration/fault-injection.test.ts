import { describe, it, expect, beforeEach } from 'vitest'
import { InMemoryBackend } from '../../src/index.js'
import {
  BackendUnavailableError,
  SecretNotFoundError,
  SigningKeyNotFoundError,
  SigningKeyAlreadyExistsError,
  InvalidAlgorithmError,
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

  describe('clear() teardown', () => {
    // Regression: clear() documented itself as full teardown but left armed
    // faults in place, so a persistent fault from one test case leaked into
    // the next test's fresh-looking backend.
    it('disarms a persistent fault, so a reused backend is fault-free afterward', async () => {
      backend.injectFault('store', 'permission-denied', { persistent: true })
      await expect(backend.store('k', 'v')).rejects.toBeInstanceOf(AuthorizationDeniedError)

      backend.clear()

      await expect(backend.store('k', 'v')).resolves.toBeUndefined()
    })

    it('disarms a one-shot fault as well as stored secrets', async () => {
      backend.injectFault('retrieve', 'backend-unavailable')

      backend.clear()

      await expect(backend.retrieve('k')).rejects.toBeInstanceOf(SecretNotFoundError)
    })
  })

  describe('mode -> typed error mapping', () => {
    it('backend-unavailable -> BackendUnavailableError', async () => {
      backend.injectFault('store', 'backend-unavailable')
      await expect(backend.store('k', 'v')).rejects.toBeInstanceOf(BackendUnavailableError)
    })

    it('key-absent on a plain secret operation -> SecretNotFoundError, including the id', async () => {
      await backend.store('k', 'v')
      backend.injectFault('retrieve', 'key-absent')
      const err = await backend.retrieve('k').catch((e: unknown) => e)
      expect(err).toBeInstanceOf(SecretNotFoundError)
      if (err instanceof SecretNotFoundError) {
        expect(err.message).toContain('k')
      }
    })

    it('key-absent on delete/exists also includes the id in the error message', async () => {
      backend.injectFault('delete', 'key-absent')
      const deleteErr = await backend.delete('the-id').catch((e: unknown) => e)
      expect(deleteErr).toBeInstanceOf(SecretNotFoundError)
      if (deleteErr instanceof SecretNotFoundError) {
        expect(deleteErr.message).toContain('the-id')
      }

      backend.injectFault('exists', 'key-absent')
      const existsErr = await backend.exists('another-id').catch((e: unknown) => e)
      expect(existsErr).toBeInstanceOf(SecretNotFoundError)
      if (existsErr instanceof SecretNotFoundError) {
        expect(existsErr.message).toContain('another-id')
      }
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

    // Regression: injecting 'key-absent' against 'generateSigningKey' has no
    // sensible meaning — enrollment has no existing key to be "absent" — so
    // arming it is rejected loudly at arm time rather than silently accepted
    // and misreported later.
    it('rejects arming key-absent against generateSigningKey at arm time', async () => {
      expect(() => {
        backend.injectFault('generateSigningKey', 'key-absent')
      }).toThrow(/key-absent.*generateSigningKey/)
      // The rejection must not leave a fault armed for the operation.
      await expect(backend.generateSigningKey('new-key', 'EdDSA')).resolves.toBeUndefined()
    })
  })

  describe('error precedence on generateSigningKey', () => {
    // Coverage addition: pins the ordering when multiple failure conditions
    // could apply — an armed fault always wins, then invalid-algorithm,
    // then already-exists.
    it('an armed fault fires before invalid-algorithm and already-exists checks', async () => {
      backend.injectFault('generateSigningKey', 'backend-unavailable')
      await expect(
        // @ts-expect-error - deliberately invalid algorithm to prove fault precedence
        backend.generateSigningKey('sk', 'not-a-real-algorithm'),
      ).rejects.toBeInstanceOf(BackendUnavailableError)
    })

    it('invalid-algorithm fires before already-exists when no fault is armed', async () => {
      await backend.generateSigningKey('sk', 'EdDSA')
      await expect(
        // @ts-expect-error - deliberately invalid algorithm to prove precedence over already-exists
        backend.generateSigningKey('sk', 'not-a-real-algorithm'),
      ).rejects.toBeInstanceOf(InvalidAlgorithmError)
    })

    it('already-exists fires when the algorithm is valid and no fault is armed', async () => {
      await backend.generateSigningKey('sk', 'EdDSA')
      await expect(backend.generateSigningKey('sk', 'EdDSA')).rejects.toBeInstanceOf(
        SigningKeyAlreadyExistsError,
      )
    })
  })

  describe('secret/signing-key namespace coexistence', () => {
    // Coverage addition mirroring the Rust FileBackend's namespace separation
    // (issue #295): the same id can name both a plain secret and a signing
    // key at once, and deleting one leaves the other fully intact.
    it('the same id can hold a secret and a signing key simultaneously, independently', async () => {
      await backend.store('x', 'secret-value')
      await backend.generateSigningKey('x', 'EdDSA')

      expect(await backend.retrieve('x')).toBe('secret-value')
      const publicKey = await backend.getPublicKey('x')
      expect(publicKey.algorithm).toBe('EdDSA')
      const signature = await backend.signWithKey('x', Buffer.from('payload'))
      expect(signature.byteLength).toBeGreaterThan(0)

      await backend.delete('x')

      await expect(backend.retrieve('x')).rejects.toBeInstanceOf(SecretNotFoundError)
      // The signing key under the same id survives the secret's deletion.
      const survivingKey = await backend.getPublicKey('x')
      expect(survivingKey.kid).toBe(publicKey.kid)
    })
  })
})
