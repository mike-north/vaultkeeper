import { describe, it, expect, beforeEach } from 'vitest'
import { TestVault } from '../../src/index.js'
import {
  BackendUnavailableError,
  SecretNotFoundError,
  SigningKeyNotFoundError,
  AuthorizationDeniedError,
  BackendLockedError,
} from 'vaultkeeper'

/**
 * Acceptance criterion 4: for each of the four failure modes, assert the
 * exact typed error class surfaces THROUGH THE REAL VaultKeeper API — not
 * merely at the backend boundary. `TestVault` wires `InMemoryBackend` into a
 * real `VaultKeeper` instance (see `TestVault.create`), so calling through
 * `vault.keeper`/the `vault` convenience methods exercises the consumer's
 * exact call path, catching the class its own `catch` block would see.
 */
describe('fault injection surfaces through the real VaultKeeper API', () => {
  let vault: TestVault

  beforeEach(async () => {
    vault = await TestVault.create()
  })

  it('backend-unavailable: VaultKeeper.store() throws BackendUnavailableError', async () => {
    vault.backend.injectFault('store', 'backend-unavailable')
    await expect(vault.keeper.store('my-secret', 'value')).rejects.toBeInstanceOf(
      BackendUnavailableError,
    )
  })

  it('key-absent (secret): VaultKeeper.setup() throws SecretNotFoundError for a plain get', async () => {
    // setup() reads the secret via backend.retrieve() — never stored, so the
    // real store is already empty; the fault forces the same error deterministically.
    vault.backend.injectFault('retrieve', 'key-absent')
    await expect(vault.setup('never-stored')).rejects.toBeInstanceOf(SecretNotFoundError)
  })

  it('key-absent (signing key): VaultKeeper.exportPublicKey() throws SigningKeyNotFoundError', async () => {
    await vault.keeper.createSigningKey('doc-signer', 'EdDSA')
    vault.backend.injectFault('getPublicKey', 'key-absent')
    await expect(vault.keeper.exportPublicKey('doc-signer')).rejects.toBeInstanceOf(
      SigningKeyNotFoundError,
    )
  })

  it('permission-denied: VaultKeeper.delete() throws AuthorizationDeniedError', async () => {
    await vault.store('to-delete', 'value')
    vault.backend.injectFault('delete', 'permission-denied')
    await expect(vault.keeper.delete('to-delete')).rejects.toBeInstanceOf(AuthorizationDeniedError)
  })

  it('session-expired: VaultKeeper.secretExists() throws BackendLockedError', async () => {
    await vault.store('present', 'value')
    vault.backend.injectFault('exists', 'session-expired')
    await expect(vault.keeper.secretExists('present')).rejects.toBeInstanceOf(BackendLockedError)
  })

  it('one-shot fault clears after surfacing through the real API once', async () => {
    vault.backend.injectFault('store', 'backend-unavailable')
    await expect(vault.keeper.store('a', '1')).rejects.toBeInstanceOf(BackendUnavailableError)
    // Cleared — the next identical call through the same real API succeeds.
    await expect(vault.keeper.store('a', '1')).resolves.toBeUndefined()
  })

  it('persistent fault keeps surfacing through the real API until cleared', async () => {
    vault.backend.injectFault('store', 'permission-denied', { persistent: true })
    await expect(vault.keeper.store('a', '1')).rejects.toBeInstanceOf(AuthorizationDeniedError)
    await expect(vault.keeper.store('a', '1')).rejects.toBeInstanceOf(AuthorizationDeniedError)
    vault.backend.clearFault('store')
    await expect(vault.keeper.store('a', '1')).resolves.toBeUndefined()
  })
})
