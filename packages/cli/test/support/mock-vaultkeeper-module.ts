/**
 * Builds a partial replacement for the `vaultkeeper` module to return from a
 * `vi.mock('vaultkeeper', ...)` factory: spreads every real export (keeping
 * `ConfigParseError`/`ConfigValidationError` etc. real, since `formatError`'s
 * `instanceof` checks against them — issue #114 — need to keep working under
 * mocking) and layers `overrides` on top for the entry points the calling
 * suite controls.
 *
 * `vi.mock` factories are hoisted above the rest of the file, so a static
 * top-level import of this helper is not safe to reference inside the
 * factory callback. Pull it in with a dynamic `import()` from inside the
 * factory instead:
 *
 * ```ts
 * const mockInit = vi.hoisted(() => vi.fn())
 *
 * vi.mock('vaultkeeper', async (importOriginal) => {
 *   const { mockVaultkeeperModule } = await import('../../support/mock-vaultkeeper-module.js')
 *   return mockVaultkeeperModule(importOriginal, {
 *     VaultKeeper: { init: mockInit },
 *   })
 * })
 * ```
 */
export async function mockVaultkeeperModule<
  TOverrides extends Partial<Record<keyof typeof import('vaultkeeper'), unknown>>,
>(
  importOriginal: <T>() => Promise<T>,
  overrides: TOverrides,
): Promise<typeof import('vaultkeeper') & TOverrides> {
  const actual = await importOriginal<typeof import('vaultkeeper')>()
  return {
    ...actual,
    ...overrides,
  }
}
