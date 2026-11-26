/**
 * Type-level tests for the {@link SetupOptions} discriminated union and the
 * {@link VaultKeeper.setup} signature (issue #193 item 1).
 *
 * The public contract is that `setup()` requires the options argument and it
 * must carry **exactly one** trust choice — either `executablePath` (TOFU
 * verification) or `skipTrust: true` (development opt-out), never both and never
 * neither. These assertions fail the type-check build if that contract ever
 * regresses (e.g. `setup('X')` starts compiling again).
 *
 * @see ../../src/vault.ts — SetupOptions / VaultKeeper.setup
 */
import { describe, expectTypeOf, it } from 'vitest'

import type { SetupOptions, SetupOptionsBase } from '../../src/index.js'
import { VaultKeeper } from '../../src/index.js'

declare const vault: VaultKeeper

describe('SetupOptions trust-choice XOR (type-level)', () => {
  it('accepts each valid single-choice form', () => {
    // executablePath alone — the production TOFU choice.
    void vault.setup('X', { executablePath: '/usr/local/bin/my-tool' })
    // skipTrust: true alone — the development opt-out.
    void vault.setup('X', { skipTrust: true })
    // A trust choice combined with base options is still valid.
    void vault.setup('X', { executablePath: '/usr/local/bin/my-tool', ttlMinutes: 5 })
    void vault.setup('X', { skipTrust: true, useLimit: 3, trustTier: 2 })
  })

  it('rejects a missing options argument', () => {
    // @ts-expect-error — the options argument is required (no bare setup('X')).
    void vault.setup('X')
  })

  it('rejects an options object with no trust choice', () => {
    // @ts-expect-error — {} satisfies neither branch of the union.
    void vault.setup('X', {})
    // @ts-expect-error — base-only options still lack the mandatory trust choice.
    void vault.setup('X', { ttlMinutes: 5 })
  })

  it('rejects supplying both trust choices at once', () => {
    // @ts-expect-error — executablePath and skipTrust are mutually exclusive.
    void vault.setup('X', { executablePath: '/usr/local/bin/my-tool', skipTrust: true })
  })

  it('rejects skipTrust: false (not an affirmative opt-out)', () => {
    // @ts-expect-error — only skipTrust: true is a valid choice; false is not.
    void vault.setup('X', { skipTrust: false })
  })

  it('models the union as base ∧ (executablePath XOR skipTrust)', () => {
    // Each valid single-choice object is assignable to SetupOptions.
    expectTypeOf<{ executablePath: string }>().toExtend<SetupOptions>()
    expectTypeOf<{ skipTrust: true }>().toExtend<SetupOptions>()

    // The common (non-trust) fields all live on SetupOptionsBase.
    expectTypeOf<SetupOptionsBase>().toHaveProperty('ttlMinutes')
    expectTypeOf<SetupOptionsBase>().toHaveProperty('useLimit')
    expectTypeOf<SetupOptionsBase>().toHaveProperty('trustTier')
    expectTypeOf<SetupOptionsBase>().toHaveProperty('backendType')

    // Every SetupOptions value carries the base fields via the intersection.
    expectTypeOf<SetupOptions>().toHaveProperty('ttlMinutes')
  })
})
