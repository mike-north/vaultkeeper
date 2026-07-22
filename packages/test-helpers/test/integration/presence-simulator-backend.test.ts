/**
 * Integration tests for {@link PresenceSimulatorBackend} driven through a real
 * `VaultKeeper` instance — issue #311.
 *
 * These cover the central acceptance criteria:
 *  - AC2 (integration) negative path — an automation-shaped signer attempting
 *    a presence-required operation is refused with a typed `NotCapableError`
 *    BEFORE the backend is touched, driven through vaultkeeper's existing
 *    fail-closed enforcement (`VaultKeeper#enforcePresenceRequirement`), not a
 *    bespoke simulated refusal.
 *  - AC3 (integration) positive path — a presence-granting configuration
 *    satisfies a presence-required operation.
 *
 * Both `store` (a plain secret operation) and `sign` (the stakeholder's
 * motivating "automation signer" scenario, see issue #307) are exercised so
 * the fail-closed enforcement is proven for both keyed-operation families the
 * vault gates: `VaultKeeper.store` and `VaultKeeper.sign`.
 */
import { describe, it, expect, vi } from 'vitest'
import { PresenceSimulatorBackend } from '../../src/index.js'
import { VaultKeeper, NotCapableError } from 'vaultkeeper'

describe('PresenceSimulatorBackend — negative path via VaultKeeper.store (AC2)', () => {
  it('refuses an automation-shaped store with NotCapableError before the backend is touched', async () => {
    // Default outcome script: every operation is 'not-capable' — an
    // automation signer with no presence mechanism at all.
    const backend = PresenceSimulatorBackend.forTesting()
    const storeSpy = vi.spyOn(backend, 'store')

    const keeper = await VaultKeeper.init({ skipDoctor: true, backend })

    await expect(
      keeper.store('automation-secret', 'value', { requirePresencePerUse: true }),
    ).rejects.toBeInstanceOf(NotCapableError)

    // "Before the backend is touched": the vault's own fail-closed
    // enforcement (VaultKeeper#enforcePresenceRequirement) must reject the
    // request without ever calling the backend's store() method.
    expect(storeSpy).not.toHaveBeenCalled()
  })

  it('refuses when the operation is explicitly scripted not-capable alongside other capable operations', async () => {
    // Presence-capable for 'delete', but explicitly not-capable for 'store' —
    // proves enforcement is operation-scoped, not a blanket backend flag.
    const backend = PresenceSimulatorBackend.forTesting({
      operations: { delete: 'grant', store: 'not-capable' },
    })
    const storeSpy = vi.spyOn(backend, 'store')
    const keeper = await VaultKeeper.init({ skipDoctor: true, backend })

    await expect(
      keeper.store('automation-secret', 'value', { requirePresencePerUse: true }),
    ).rejects.toBeInstanceOf(NotCapableError)
    expect(storeSpy).not.toHaveBeenCalled()
  })
})

describe('PresenceSimulatorBackend — positive path via VaultKeeper.store (AC3)', () => {
  it('satisfies a presence-required store when the backend grants presence', async () => {
    const backend = PresenceSimulatorBackend.forTesting({ operations: { store: 'grant' } })
    const keeper = await VaultKeeper.init({ skipDoctor: true, backend })

    await expect(
      keeper.store('presence-backed-secret', 'value', { requirePresencePerUse: true }),
    ).resolves.toBeUndefined()
    await expect(backend.exists('presence-backed-secret')).resolves.toBe(true)
  })
})

describe('PresenceSimulatorBackend — negative path via VaultKeeper.sign (AC2, stakeholder scenario)', () => {
  it('refuses an automation signer with NotCapableError before the backend signs', async () => {
    const backend = PresenceSimulatorBackend.forTesting()
    const keeper = await VaultKeeper.init({ skipDoctor: true, backend })

    await keeper.createSigningKey('doc-signer', 'EdDSA')
    const token = await keeper.authorizeSigningKey('doc-signer')

    const signWithKeySpy = vi.spyOn(backend, 'signWithKey')

    await expect(
      keeper.sign(token, { payload: 'agent-authored payload' }, { requirePresencePerUse: true }),
    ).rejects.toBeInstanceOf(NotCapableError)
    expect(signWithKeySpy).not.toHaveBeenCalled()
  })
})

describe('PresenceSimulatorBackend — positive path via VaultKeeper.sign (AC3, stakeholder scenario)', () => {
  it('satisfies a presence-required signature when the backend grants presence', async () => {
    const backend = PresenceSimulatorBackend.forTesting({ operations: { sign: 'grant' } })
    const keeper = await VaultKeeper.init({ skipDoctor: true, backend })

    await keeper.createSigningKey('doc-signer', 'EdDSA')
    const token = await keeper.authorizeSigningKey('doc-signer')

    const { result } = await keeper.sign(
      token,
      { payload: 'human-witnessed payload' },
      { requirePresencePerUse: true },
    )
    expect(result.jws).toBeDefined()
  })
})
