/**
 * Type-level tests for {@link PresenceSimulatorBackend} — issue #311
 * acceptance criterion 5 (unit, guard 2: no default constructor).
 *
 * The only construction path is the named opt-in
 * `PresenceSimulatorBackend.forTesting(...)`; the class's constructor is
 * `private`, so `new PresenceSimulatorBackend(...)` must fail to compile from
 * outside the class. Per CLAUDE.md's type-level-test convention, this uses
 * vitest's typecheck mode (`@ts-expect-error`) rather than `tsd`.
 *
 * @see ../../src/presence-simulator-backend.ts
 */
import { describe, expectTypeOf, it } from 'vitest'

import { PresenceSimulatorBackend } from '../../src/index.js'

describe('PresenceSimulatorBackend has no default constructor (type-level)', () => {
  it('rejects direct construction with `new`', () => {
    // @ts-expect-error — the constructor is private; `forTesting()` is the
    // only construction path (guard 2).
    new PresenceSimulatorBackend()
  })

  it('accepts construction only through the named forTesting() opt-in', () => {
    expectTypeOf<typeof PresenceSimulatorBackend.forTesting>().returns.toEqualTypeOf<PresenceSimulatorBackend>()

    // Called with no options — every operation defaults to 'not-capable'.
    const backend = PresenceSimulatorBackend.forTesting()
    expectTypeOf(backend).toEqualTypeOf<PresenceSimulatorBackend>()

    // Called with a scripted outcome per operation.
    PresenceSimulatorBackend.forTesting({ operations: { store: 'grant' } })
  })
})
