/**
 * Type-level tests for {@link UnreachableError}'s `never` constructor
 * parameter (issue #340).
 *
 * The contract: `UnreachableError`'s first constructor parameter is typed
 * `never`, so it can only be constructed with a value the compiler has
 * already narrowed to `never` — i.e. every member of a discriminated union
 * has been handled by a preceding `case`. Passing anything else (a value
 * that still carries a non-`never` type, meaning some union member was
 * missed) is a compile-time error at the call site, not just a runtime
 * throw. This is the exhaustiveness pattern the `kty`/`ClaimsKind` switch in
 * `jwe/claims.ts` uses in production.
 *
 * @see ../../src/errors.ts — UnreachableError
 * @see ../../src/jwe/claims.ts — production exhaustiveness usage
 */
import { describe, expectTypeOf, it } from 'vitest'

import { UnreachableError } from '../../src/index.js'

type Shape = { kind: 'circle'; radius: number } | { kind: 'square'; side: number }

// A genuinely exhaustive switch: every Shape variant has a `case`, so
// `shape` is narrowed to `never` in the `default` arm and this module
// compiles cleanly. If a new Shape variant were added without a matching
// `case`, `shape` would no longer be `never` here and the file would fail
// to compile — this is the positive half of the exhaustiveness contract.
function describeShape(shape: Shape): string {
  switch (shape.kind) {
    case 'circle':
      return `circle r=${String(shape.radius)}`
    case 'square':
      return `square s=${String(shape.side)}`
    default:
      throw new UnreachableError(shape)
  }
}

declare const unnarrowedValue: string

describe('UnreachableError constructor (type-level exhaustiveness)', () => {
  it('accepts a value the compiler has narrowed to never', () => {
    // Proven by `describeShape` above compiling at all: its `default` arm
    // constructs `UnreachableError` from `shape`, which only typechecks
    // because the switch is exhaustive and narrows `shape` to `never` there.
    expectTypeOf(describeShape).returns.toBeString()
  })

  it('rejects a non-never value at the call site', () => {
    // @ts-expect-error — a plain `string` is not `never`; only a value fully
    // narrowed by an exhaustive switch satisfies the constructor's first
    // parameter.
    new UnreachableError(unnarrowedValue)
  })

  it('rejects a value from a non-exhausted union member', () => {
    // A union whose switch is missing a case for 'triangle' — this is the
    // shape a missed union arm actually produces.
    type IncompleteShape = { kind: 'circle'; radius: number } | { kind: 'triangle'; base: number }

    function widen(shape: IncompleteShape): void {
      switch (shape.kind) {
        case 'circle':
          return
        default:
          // @ts-expect-error — 'triangle' was never handled by a `case`
          // above, so `shape` here is still narrowed to
          // `{ kind: 'triangle'; base: number }`, not `never`.
          throw new UnreachableError(shape)
      }
    }
    void widen
  })
})
