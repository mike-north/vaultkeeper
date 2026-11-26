import { describe, it, expect } from 'vitest'
import { FaultPlan } from '../../src/index.js'

/**
 * `FaultPlan` is the backend-agnostic scripting mechanism `InMemoryBackend`
 * holds internally (see `packages/test-helpers/test/integration/fault-injection.test.ts`
 * for its behavior as consulted by a real double). These tests exercise the
 * standalone helper directly, confirming it knows nothing about any
 * particular backend's storage or resource namespaces — it only tracks which
 * operation key has which mode armed, and for how long.
 */
describe('FaultPlan', () => {
  it('consume() returns undefined when no fault is armed', () => {
    const plan = new FaultPlan<'read' | 'write'>()
    expect(plan.consume('read')).toBeUndefined()
  })

  it('one-shot: consume() returns the mode once, then clears itself', () => {
    const plan = new FaultPlan<'read' | 'write'>()
    plan.inject('read', 'backend-unavailable')

    expect(plan.consume('read')).toBe('backend-unavailable')
    expect(plan.consume('read')).toBeUndefined()
  })

  it('persistent: consume() keeps returning the mode until clear()', () => {
    const plan = new FaultPlan<'read' | 'write'>()
    plan.inject('read', 'permission-denied', { persistent: true })

    expect(plan.consume('read')).toBe('permission-denied')
    expect(plan.consume('read')).toBe('permission-denied')

    plan.clear('read')
    expect(plan.consume('read')).toBeUndefined()
  })

  it('is scoped per operation key', () => {
    const plan = new FaultPlan<'read' | 'write'>()
    plan.inject('read', 'session-expired')

    expect(plan.consume('write')).toBeUndefined()
    expect(plan.consume('read')).toBe('session-expired')
  })

  it('clearAll() removes every armed fault regardless of mode or persistence', () => {
    const plan = new FaultPlan<'read' | 'write'>()
    plan.inject('read', 'key-absent', { persistent: true })
    plan.inject('write', 'backend-unavailable')

    plan.clearAll()

    expect(plan.consume('read')).toBeUndefined()
    expect(plan.consume('write')).toBeUndefined()
  })

  it('re-injecting a fault for an operation replaces the previous one', () => {
    const plan = new FaultPlan<'read' | 'write'>()
    plan.inject('read', 'backend-unavailable', { persistent: true })
    plan.inject('read', 'permission-denied', { persistent: true })

    expect(plan.consume('read')).toBe('permission-denied')
  })
})
