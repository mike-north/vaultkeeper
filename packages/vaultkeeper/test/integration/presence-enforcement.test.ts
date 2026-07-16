/**
 * Integration tests for require-presence-per-use enforcement in the shared
 * VaultKeeper access path (issue #122).
 *
 * Enforcement lives in one place — the vault's backend-touching operations
 * (`store`/`delete`/`setup`/`sign`) — not per CLI command. These tests drive
 * that shared path directly with a mock presence backend so the guarantee is
 * proven independently of any hardware.
 *
 * @see https://github.com/mike-north/vaultkeeper/issues/122
 */

import * as crypto from 'node:crypto'
import { describe, it, expect } from 'vitest'
import { VaultKeeper } from '../../src/index.js'
import {
  NotCapableError,
  PresenceDeclinedError,
  PresenceTimeoutError,
  AuthorizationDeniedError,
  DeviceNotPresentError,
} from '../../src/errors.js'
import { MockPresenceBackend } from '../helpers/presence-backend.js'

async function vaultWith(backend: MockPresenceBackend): Promise<VaultKeeper> {
  return VaultKeeper.init({ skipDoctor: true, backend })
}

describe('NotCapableError before any backend touch (AC3)', () => {
  it('store with requirePresencePerUse against a non-capable backend throws before touching it', async () => {
    const backend = new MockPresenceBackend({ presencePerUse: false })
    const vault = await vaultWith(backend)

    await expect(vault.store('k', 'v', { requirePresencePerUse: true })).rejects.toBeInstanceOf(
      NotCapableError,
    )

    // The backend's keyed path was never reached — refusal happened first.
    expect(backend.freshActionDemands).toBe(0)
  })

  it('NotCapableError carries machine-readable fields and names qualifying backends', async () => {
    const backend = new MockPresenceBackend({ presencePerUse: false })
    const vault = await vaultWith(backend)

    const err = await vault
      .store('k', 'v', { requirePresencePerUse: true })
      .then(() => undefined)
      .catch((e: unknown) => e)

    expect(err).toBeInstanceOf(NotCapableError)
    if (err instanceof NotCapableError) {
      expect(err.backendType).toBe('mock-presence')
      expect(err.capability).toBe('presencePerUse')
      // Message must point the caller at backends that can satisfy the flag.
      expect(err.message).toContain('YubiKey')
      expect(err.message).toContain('1Password')
    }
  })

  it('delete and setup also refuse before touching the backend', async () => {
    const backend = new MockPresenceBackend({ presencePerUse: false })
    const vault = await vaultWith(backend)

    await expect(vault.delete('k', { requirePresencePerUse: true })).rejects.toBeInstanceOf(
      NotCapableError,
    )
    await expect(
      vault.setup('k', { skipTrust: true, requirePresencePerUse: true }),
    ).rejects.toBeInstanceOf(NotCapableError)

    expect(backend.freshActionDemands).toBe(0)
  })

  it('without the flag, a non-capable backend is not gated', async () => {
    // requirePresencePerUse defaults off; the InMemory-like mock still requires
    // a primed action for its own keyed op, so priming lets the store succeed.
    const backend = new MockPresenceBackend({ presencePerUse: false })
    backend.arm('approve')
    const vault = await vaultWith(backend)
    await expect(vault.store('k', 'v')).resolves.toBeUndefined()
  })
})

describe('capabilities queried fresh per call (AC4)', () => {
  it('two operations each query capabilities and each force a fresh action', async () => {
    const backend = new MockPresenceBackend({ presencePerUse: true })
    backend.arm('approve', 2)
    const vault = await vaultWith(backend)

    await vault.store('a', '1', { requirePresencePerUse: true })
    await vault.store('b', '2', { requirePresencePerUse: true })

    // No caching across operations: capabilities re-queried for each call.
    expect(backend.getCapabilitiesCalls).toBe(2)
    // Each call forced its own fresh action regardless of the first's state.
    expect(backend.freshActionDemands).toBe(2)
  })
})

describe('declined and timeout produce distinct typed errors (AC5)', () => {
  it('a declined presence action throws PresenceDeclinedError', async () => {
    const backend = new MockPresenceBackend({ presencePerUse: true })
    backend.arm('decline')
    const vault = await vaultWith(backend)

    const err = await vault
      .store('k', 'v', { requirePresencePerUse: true })
      .then(() => undefined)
      .catch((e: unknown) => e)

    expect(err).toBeInstanceOf(PresenceDeclinedError)
    expect(err).not.toBeInstanceOf(PresenceTimeoutError)
    expect(err).not.toBeInstanceOf(AuthorizationDeniedError)
    if (err instanceof PresenceDeclinedError) {
      expect(err.backendType).toBe('mock-presence')
    }
  })

  it('a timed-out presence action throws PresenceTimeoutError with timeoutMs', async () => {
    const backend = new MockPresenceBackend({ presencePerUse: true, timeoutMs: 2500 })
    // Not armed → the demand times out.
    const vault = await vaultWith(backend)

    const err = await vault
      .store('k', 'v', { requirePresencePerUse: true })
      .then(() => undefined)
      .catch((e: unknown) => e)

    expect(err).toBeInstanceOf(PresenceTimeoutError)
    expect(err).not.toBeInstanceOf(PresenceDeclinedError)
    expect(err).not.toBeInstanceOf(DeviceNotPresentError)
    if (err instanceof PresenceTimeoutError) {
      expect(err.backendType).toBe('mock-presence')
      expect(err.timeoutMs).toBe(2500)
    }
  })
})

describe('non-bypassability across consecutive operations (AC6)', () => {
  it('two consecutive required-presence operations each demand a distinct fresh action', async () => {
    const backend = new MockPresenceBackend({ presencePerUse: true })
    // Only ONE fresh action is primed.
    backend.arm('approve', 1)
    const vault = await vaultWith(backend)

    // First operation consumes the single primed action.
    await expect(vault.store('a', '1', { requirePresencePerUse: true })).resolves.toBeUndefined()

    // The second operation must NOT be satisfied by the first's resolution or
    // any cached material — it demands its own fresh action, which is absent.
    await expect(vault.store('b', '2', { requirePresencePerUse: true })).rejects.toBeInstanceOf(
      PresenceTimeoutError,
    )

    // Both operations reached the fresh-action demand independently.
    expect(backend.freshActionDemands).toBe(2)
  })

  it('with a fresh action primed for each, both operations succeed', async () => {
    const backend = new MockPresenceBackend({ presencePerUse: true })
    backend.arm('approve', 2)
    const vault = await vaultWith(backend)

    await expect(vault.store('a', '1', { requirePresencePerUse: true })).resolves.toBeUndefined()
    await expect(vault.store('b', '2', { requirePresencePerUse: true })).resolves.toBeUndefined()
    expect(backend.freshActionDemands).toBe(2)
  })
})

describe('presence-gated signing (AC7)', () => {
  it('each sign performs a fresh backend signWithKey round-trip demanding a fresh action', async () => {
    const backend = new MockPresenceBackend({ presencePerUse: true })
    const vault = await vaultWith(backend)

    // Enrollment does not demand presence.
    await vault.createSigningKey('approval', 'EdDSA')
    expect(backend.freshActionDemands).toBe(0)

    const pub = await vault.exportPublicKey('approval')
    const token = await vault.authorizeSigningKey('approval')

    backend.arm('approve', 2)
    const { result: first } = await vault.sign(
      token,
      { payload: 'gate-1' },
      { requirePresencePerUse: true },
    )
    const { result: second } = await vault.sign(
      token,
      { payload: 'gate-2' },
      { requirePresencePerUse: true },
    )

    // Two sign calls → two fresh signWithKey round-trips → two fresh actions.
    expect(backend.freshActionDemands).toBe(2)

    // Both produced valid, distinct EdDSA signatures verifiable with the public
    // key — no cached key material could have satisfied either.
    expect(first.jws).not.toBe(second.jws)
    await expect(
      VaultKeeper.verify({ payload: 'gate-1', jws: first.jws, publicKey: pub.publicKeyPem }),
    ).resolves.toBe(true)
  })

  it('a second required-presence sign is not satisfied by the first sign', async () => {
    const backend = new MockPresenceBackend({ presencePerUse: true })
    const vault = await vaultWith(backend)
    await vault.createSigningKey('approval', 'EdDSA')
    const token = await vault.authorizeSigningKey('approval')

    backend.arm('approve', 1)
    await vault.sign(token, { payload: 'a' }, { requirePresencePerUse: true })
    await expect(
      vault.sign(token, { payload: 'b' }, { requirePresencePerUse: true }),
    ).rejects.toBeInstanceOf(PresenceTimeoutError)
  })

  it('signing against a non-capable backend refuses before any signWithKey', async () => {
    const backend = new MockPresenceBackend({ presencePerUse: false })
    const vault = await vaultWith(backend)
    await vault.createSigningKey('approval', 'EdDSA')
    const token = await vault.authorizeSigningKey('approval')

    await expect(
      vault.sign(token, { payload: 'a' }, { requirePresencePerUse: true }),
    ).rejects.toBeInstanceOf(NotCapableError)
    expect(backend.freshActionDemands).toBe(0)
  })
})

describe('operation-aware, fail-closed enforcement (1Password per-access shape)', () => {
  // Models 1Password per-access: presence-capable, but only the 'read'
  // operation forces a fresh action — store/delete route through a cached
  // session. A flagged store/delete must fail closed (NotCapableError), never
  // silently pass without a fresh action. There is no third outcome.
  function readOnlyPresenceBackend(): MockPresenceBackend {
    return new MockPresenceBackend({ presencePerUse: true, enforcedOperations: ['read'] })
  }

  it('a flagged store is refused with NotCapableError, before any fresh action', async () => {
    const backend = readOnlyPresenceBackend()
    const vault = await vaultWith(backend)

    const err = await vault
      .store('k', 'v', { requirePresencePerUse: true })
      .then(() => undefined)
      .catch((e: unknown) => e)

    expect(err).toBeInstanceOf(NotCapableError)
    if (err instanceof NotCapableError) {
      expect(err.backendType).toBe('mock-presence')
      // The message names the covered operation and the refused one.
      expect(err.message).toContain('read')
      expect(err.message).toContain('store')
    }
    // Fail closed: no fresh action was demanded and nothing was stored.
    expect(backend.freshActionDemands).toBe(0)
  })

  it('a flagged delete is refused with NotCapableError', async () => {
    const backend = readOnlyPresenceBackend()
    const vault = await vaultWith(backend)
    await expect(vault.delete('k', { requirePresencePerUse: true })).rejects.toBeInstanceOf(
      NotCapableError,
    )
    expect(backend.freshActionDemands).toBe(0)
  })

  it('a flagged read (setup) is covered: it forces a fresh action and succeeds', async () => {
    const backend = readOnlyPresenceBackend()
    const vault = await vaultWith(backend)

    // Seed the secret through an unflagged store (still needs a primed action —
    // the mock is a touch device — but no presence *requirement* is asserted).
    backend.arm('approve')
    await vault.store('k', 'v')

    // The read IS covered, so enforcement passes and the retrieve forces its own
    // fresh action; setup returns a JWE.
    backend.arm('approve')
    const jwe = await vault.setup('k', { skipTrust: true, requirePresencePerUse: true })
    expect(typeof jwe).toBe('string')
    // One action for the seed store, one for the presence-gated read.
    expect(backend.freshActionDemands).toBe(2)
  })
})

describe('getActiveBackendCapabilities introspection (AC8)', () => {
  it('reports the active backend instance capabilities (capable)', async () => {
    const vault = await vaultWith(new MockPresenceBackend({ presencePerUse: true }))
    await expect(vault.getActiveBackendCapabilities()).resolves.toEqual({ presencePerUse: true })
  })

  it('reports the active backend instance capabilities (non-capable)', async () => {
    const vault = await vaultWith(new MockPresenceBackend({ presencePerUse: false }))
    await expect(vault.getActiveBackendCapabilities()).resolves.toEqual({ presencePerUse: false })
  })

  it('defaults to false for an active backend that does not implement the interface', async () => {
    const vault = await VaultKeeper.init({
      skipDoctor: true,
      backend: {
        type: 'plain',
        displayName: 'Plain',
        isAvailable: () => Promise.resolve(true),
        store: () => Promise.resolve(),
        retrieve: () => Promise.resolve(crypto.randomUUID()),
        delete: () => Promise.resolve(),
        exists: () => Promise.resolve(false),
      },
    })
    await expect(vault.getActiveBackendCapabilities()).resolves.toEqual({ presencePerUse: false })
  })
})
