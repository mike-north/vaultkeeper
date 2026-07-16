/**
 * Type-level tests for `mockVaultkeeperModule`'s `overrides` constraint
 * (issue #199 — consolidated onto vitest's typecheck mode; see
 * `packages/vaultkeeper/test/types/setup-options.test-d.ts` for the sibling
 * example this mirrors).
 *
 * `overrides` is constrained to `keyof typeof import('vaultkeeper')` so a
 * misspelled export name fails to compile instead of silently adding a new
 * property that nothing reads — the bug PR #157's review comment flagged
 * before that constraint existed. These assertions fail the type-check run
 * (`vitest run`, via the package's `typecheck` config) if the constraint ever
 * regresses.
 *
 * @see ../support/mock-vaultkeeper-module.ts — mockVaultkeeperModule
 */
import { describe, it } from 'vitest'

import { mockVaultkeeperModule } from '../support/mock-vaultkeeper-module.js'

declare const importOriginal: <T>() => Promise<T>

describe('mockVaultkeeperModule overrides constraint (type-level)', () => {
  it('accepts overriding a real vaultkeeper export', () => {
    void mockVaultkeeperModule(importOriginal, {
      defaultBackendType: () => 'file',
    })
  })

  it('rejects a misspelled export name', () => {
    void mockVaultkeeperModule(importOriginal, {
      // @ts-expect-error — 'defaultBackendTyp' is not a key of the vaultkeeper module
      defaultBackendTyp: () => 'file',
    })
  })
})
