/**
 * Type-only regression checks for `mockVaultkeeperModule`'s `overrides`
 * constraint. Never invoked at runtime (vitest only collects `*.test.ts`) —
 * this file exists purely so `tsc` proves the constraint holds. It is picked
 * up by `tsconfig.test.json`, which is also the project ESLint's type-aware
 * config points at, so type errors here surface the same way a broken build
 * would.
 */
import { mockVaultkeeperModule } from './mock-vaultkeeper-module.js'

function _typeOnlyChecks(importOriginal: <T>() => Promise<T>): void {
  // Valid: overriding a real `vaultkeeper` export compiles.
  void mockVaultkeeperModule(importOriginal, {
    defaultBackendType: () => 'file',
  })

  // Regression: a misspelled export name must fail to compile, not silently
  // add a new property that nothing reads (the bug the review comment on
  // PR #157 flagged before `overrides` was constrained to `keyof typeof
  // import('vaultkeeper')`).
  void mockVaultkeeperModule(importOriginal, {
    // @ts-expect-error — 'defaultBackendTyp' is not a key of the vaultkeeper module
    defaultBackendTyp: () => 'file',
  })
}

void _typeOnlyChecks
