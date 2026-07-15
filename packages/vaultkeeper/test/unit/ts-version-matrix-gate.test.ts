import { describe, it, expect } from 'vitest'
import {
  shouldSkipMatrixCell,
  missingCompilerMessage,
  FIXTURES_INSTALL_COMMAND,
} from '../e2e/ts-version-matrix-gate.js'

/**
 * Unit coverage for the TS-version matrix's skip/fail predicate (issue
 * #136). The predicate decides, per matrix cell in
 * `consumer-typecheck.test.ts`, whether a missing pinned compiler is a
 * harmless local skip or a CI failure — this is the logic that must stay
 * correct so a future workflow refactor that drops the fixtures-install
 * step is caught (fails loudly) rather than silently skipping every cell.
 */
describe('ts-version matrix skip/fail predicate (issue #136)', () => {
  it('skips a missing pinned compiler outside CI', () => {
    expect(shouldSkipMatrixCell(undefined, false)).toBe(true)
  })

  it('does not skip a missing pinned compiler inside CI (so the cell runs and fails)', () => {
    expect(shouldSkipMatrixCell(undefined, true)).toBe(false)
  })

  it('runs a resolved pinned compiler outside CI', () => {
    expect(shouldSkipMatrixCell('/fixtures/typescript-5-0', false)).toBe(false)
  })

  it('runs a resolved pinned compiler inside CI', () => {
    expect(shouldSkipMatrixCell('/fixtures/typescript-5-0', true)).toBe(false)
  })

  it('names the fixtures install command in the remediation message', () => {
    const message = missingCompilerMessage('TypeScript 5.0.4 (stated floor)')
    expect(message).toContain('TypeScript 5.0.4 (stated floor)')
    expect(message).toContain(FIXTURES_INSTALL_COMMAND)
  })

  it('remediation message names a command that matches the CI install step exactly', () => {
    expect(FIXTURES_INSTALL_COMMAND).toBe(
      'pnpm --dir packages/vaultkeeper/test/e2e/ts-version-fixtures install --frozen-lockfile --ignore-workspace',
    )
  })
})
