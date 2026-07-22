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
 * Also covers the arm-per-call queue mode (`armPresence`), added so this
 * double can prove presence is demanded fresh on every call rather than
 * checked once and assumed — mirroring the Rust core's own
 * `MockPresenceBackend` arm/consume semantics
 * (`crates/vaultkeeper-core/tests/presence_capability.rs`).
 *
 * Guard 2 (no default constructor) is covered at the type level in
 * test/types/presence-simulator-backend.test-d.ts, per CLAUDE.md's
 * type-level-test convention (vitest typecheck mode, not tsd).
 */
import { describe, it, expect, afterEach } from 'vitest'
import { PresenceSimulatorBackend } from '../../src/index.js'
import {
  BackendRegistry,
  BackendUnavailableError,
  PresenceDeclinedError,
  PresenceTimeoutError,
  SecretNotFoundError,
  TestDoubleMisuseError,
} from 'vaultkeeper'

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
    // delete is scripted 'grant' and unaffected by store's refusal: the call
    // passes the presence gate and reaches the delegate, whose contract-
    // faithful delete reports the missing id — a backend-level error, not a
    // presence one, proving the grant.
    await expect(backend.delete('never-stored')).rejects.toBeInstanceOf(SecretNotFoundError)
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

  it('throws a typed TestDoubleMisuseError when NODE_ENV is production', () => {
    process.env.NODE_ENV = 'production'
    expect(() => PresenceSimulatorBackend.forTesting()).toThrow(TestDoubleMisuseError)
    expect(() => PresenceSimulatorBackend.forTesting()).toThrow(/production/i)
  })

  it('the thrown TestDoubleMisuseError names the double and the detected environment', () => {
    process.env.NODE_ENV = 'production'
    try {
      PresenceSimulatorBackend.forTesting()
      expect.unreachable('forTesting() should have thrown')
    } catch (err) {
      if (!(err instanceof TestDoubleMisuseError)) {
        throw err
      }
      expect(err.doubleName).toBe('PresenceSimulatorBackend')
      expect(err.detectedEnvironment).toBe('production')
    }
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

describe('PresenceSimulatorBackend — arm-per-call queue mode', () => {
  it('reports presence-covered once an operation has been armed, even with a static not-capable script', async () => {
    const backend = PresenceSimulatorBackend.forTesting()
    backend.armPresence('store', 'grant')
    const capabilities = await backend.getCapabilities()
    expect(capabilities.presencePerUse).toBe(true)
    expect(capabilities.presenceEnforcedOperations).toContain('store')
  })

  it('consumes exactly one armed outcome per call, in FIFO order', async () => {
    const backend = PresenceSimulatorBackend.forTesting()
    backend.armPresence('store', 'grant')
    backend.armPresence('store', 'refuse')
    await expect(backend.store('id', 'secret')).resolves.toBeUndefined()
    await expect(backend.store('id', 'secret')).rejects.toBeInstanceOf(PresenceDeclinedError)
  })

  it('throws PresenceTimeoutError when the armed queue is exhausted (an unprimed demand)', async () => {
    const backend = PresenceSimulatorBackend.forTesting()
    backend.armPresence('sign', 'grant')
    await backend.generateSigningKey('key-a', 'EdDSA')
    const data = Buffer.from('payload')
    await expect(backend.signWithKey('key-a', data)).resolves.toBeInstanceOf(Buffer)
    await expect(backend.signWithKey('key-a', data)).rejects.toBeInstanceOf(PresenceTimeoutError)
  })

  it('an armed \'timeout\' outcome throws PresenceTimeoutError for that call', async () => {
    const backend = PresenceSimulatorBackend.forTesting()
    backend.armPresence('delete', 'timeout')
    await expect(backend.delete('never-stored')).rejects.toBeInstanceOf(PresenceTimeoutError)
  })

  it('a static \'timeout\' script throws PresenceTimeoutError on every call', async () => {
    const backend = PresenceSimulatorBackend.forTesting({ operations: { read: 'timeout' } })
    await expect(backend.retrieve('id')).rejects.toBeInstanceOf(PresenceTimeoutError)
    await expect(backend.retrieve('id')).rejects.toBeInstanceOf(PresenceTimeoutError)
  })

  it('arming one operation does not affect the static script of another', async () => {
    const backend = PresenceSimulatorBackend.forTesting({ operations: { delete: 'grant' } })
    backend.armPresence('store', 'refuse')
    await expect(backend.store('id', 'secret')).rejects.toBeInstanceOf(PresenceDeclinedError)
    // Same grant-proof shape as above: a backend-level not-found (not a
    // presence error) shows delete's static grant script is unaffected.
    await expect(backend.delete('never-stored')).rejects.toBeInstanceOf(SecretNotFoundError)
  })
})
