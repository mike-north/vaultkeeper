/**
 * Skip/fail predicate for the TS-version compatibility matrix
 * (`consumer-typecheck.test.ts`, issue #125) extracted as a pure function so
 * it can be unit-tested directly, without invoking `tsc` or a CI environment
 * (see `test/unit/ts-version-matrix-gate.test.ts`).
 *
 * Outside CI, a missing pinned compiler is a real skip: installing
 * `./ts-version-fixtures` is a manual, opt-in local setup step, and a
 * developer who hasn't run it shouldn't see a failing suite.
 *
 * Inside CI (`process.env.CI` set), the fixtures install is a required
 * workflow step, so a missing compiler there means that step regressed —
 * the cell must fail loudly with a remediation message instead of quietly
 * registering as "skipped", which would silently disable the gate (#136).
 */
export function shouldSkipMatrixCell(typescriptRoot: string | undefined, isCI: boolean): boolean {
  return typescriptRoot === undefined && !isCI
}

/** Command used by both `ci.yml` and `release.yml` to install the pinned TS-version matrix compilers. */
export const FIXTURES_INSTALL_COMMAND =
  'pnpm --dir packages/vaultkeeper/test/e2e/ts-version-fixtures install --frozen-lockfile --ignore-workspace'

/** Actionable remediation message thrown when a matrix cell resolves no pinned compiler while running in CI. */
export function missingCompilerMessage(label: string): string {
  return `${label}: pinned compiler not installed — run ${FIXTURES_INSTALL_COMMAND} (CI must run this before pnpm test)`
}
