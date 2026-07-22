/**
 * Unit tests for {@link PresenceSimulatorBackend}.
 *
 * Covers issue #311 acceptance criteria:
 *  - AC1 (unit): implements PresenceCapableBackend; per-operation outcomes are
 *    scriptable across grant / refuse / not-capable in the existing
 *    BackendCapabilities vocabulary.
 *  - AC4 (unit) guard 1 — structural: the backend registry cannot construct it
 *    by type name; it is absent from register-builtins.
 *  - AC6 (unit) guard 3 — production tripwire: construction throws under
 *    NODE_ENV=production.
 *
 * Guard 2 (no default constructor) is covered at the type level in
 * test/types/presence-simulator-backend.test-d.ts, per CLAUDE.md's
 * type-level-test convention (vitest typecheck mode, not tsd).
 */
import { describe, it, expect, afterEach } from 'vitest'
import { PresenceSimulatorBackend } from '../../src/index.js'
import { BackendRegistry, BackendUnavailableError, PresenceDeclinedError } from 'vaultkeeper'

describe('PresenceSimulatorBackend — capability vocabulary (AC1)', () => {
  it('implements PresenceCapableBackend', async () => {
    const backend = PresenceSimulatorBackend.forTesting()
    expect(typeof backend.getCapabilities).toBe('function')
    await expect(backend.getCapabilities()).resolves.toBeDefined()
  })

  it('defaults every operation to not-capable when no outcomes are given', async () => {
    const backend = PresenceSimulatorBackend.forTesting()
    await expect(backend.getCapabilities()).resolves.toEqual({ presencePerUse: false })
  })

  it('reports presencePerUse: true and lists exactly the granted/refused operations', async () => {
    const backend = PresenceSimulatorBackend.forTesting({
      operations: { store: 'grant', delete: 'refuse', read: 'not-capable' },
    })
    const capabilities = await backend.getCapabilities()
    expect(capabilities.presencePerUse).toBe(true)
    expect(capabilities.presenceEnforcedOperations).toBeDefined()
    expect(new Set(capabilities.presenceEnforcedOperations)).toEqual(new Set(['store', 'delete']))
  })

  it("'grant' outcome: the scripted operation succeeds as if presence were granted", async () => {
    const backend = PresenceSimulatorBackend.forTesting({ operations: { store: 'grant' } })
    await expect(backend.store('id', 'secret')).resolves.toBeUndefined()
    await expect(backend.retrieve('id')).resolves.toBe('secret')
  })

  it("'refuse' outcome: the scripted operation throws PresenceDeclinedError", async () => {
    const backend = PresenceSimulatorBackend.forTesting({ operations: { store: 'refuse' } })
    await expect(backend.store('id', 'secret')).rejects.toBeInstanceOf(PresenceDeclinedError)
  })

  it("'refuse' only affects the scripted operation, not others", async () => {
    const backend = PresenceSimulatorBackend.forTesting({
      operations: { store: 'refuse', delete: 'grant' },
    })
    await expect(backend.store('id', 'secret')).rejects.toBeInstanceOf(PresenceDeclinedError)
    // delete is scripted 'grant' and unaffected by store's refusal.
    await expect(backend.delete('never-stored')).resolves.toBeUndefined()
  })

  it("'sign' outcome is scriptable independently of secret operations", async () => {
    const backend = PresenceSimulatorBackend.forTesting({ operations: { sign: 'refuse' } })
    await backend.generateSigningKey('key-a', 'EdDSA')
    const data = Buffer.from('payload')
    await expect(backend.signWithKey('key-a', data)).rejects.toBeInstanceOf(PresenceDeclinedError)
  })
})

describe('PresenceSimulatorBackend — guard 1: structural isolation (AC4)', () => {
  it('is absent from the set of registered backend types', () => {
    expect(BackendRegistry.getTypes()).not.toContain('presence-simulator')
  })

  it('cannot be constructed by type name through the backend registry', () => {
    expect(() => BackendRegistry.create('presence-simulator')).toThrow(BackendUnavailableError)
  })
})

describe('PresenceSimulatorBackend — guard 3: production tripwire (AC6)', () => {
  const ORIGINAL_NODE_ENV = process.env.NODE_ENV

  afterEach(() => {
    if (ORIGINAL_NODE_ENV === undefined) {
      delete process.env.NODE_ENV
    } else {
      process.env.NODE_ENV = ORIGINAL_NODE_ENV
    }
  })

  it('throws when NODE_ENV is production', () => {
    process.env.NODE_ENV = 'production'
    expect(() => PresenceSimulatorBackend.forTesting()).toThrow(/production/i)
  })

  it('succeeds when NODE_ENV is not production', () => {
    process.env.NODE_ENV = 'test'
    expect(() => PresenceSimulatorBackend.forTesting()).not.toThrow()
  })

  it('succeeds when NODE_ENV is unset', () => {
    delete process.env.NODE_ENV
    expect(() => PresenceSimulatorBackend.forTesting()).not.toThrow()
  })
})
