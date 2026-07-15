import { readFileSync } from 'node:fs'
import { resolve, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, it, expect } from 'vitest'
import {
  shouldSkipMatrixCell,
  missingCompilerMessage,
  FIXTURES_INSTALL_COMMAND,
} from '../e2e/ts-version-matrix-gate.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const repoRoot = resolve(__dirname, '..', '..', '..', '..')

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

  // The drift #136 guards against is a workflow edit dropping or changing
  // the fixtures-install step. Asserting against the workflow files (not a
  // string literal copied from the constant) means renaming the step,
  // removing it, or changing its flags fails this test at PR time, before
  // the in-CI cell failure can ever fire on a workflow run.
  it.each(['.github/workflows/ci.yml', '.github/workflows/release.yml'])(
    '%s runs the fixtures-install command the remediation message names',
    (workflow) => {
      const contents = readFileSync(resolve(repoRoot, workflow), 'utf8')
      expect(contents).toContain(FIXTURES_INSTALL_COMMAND)
    },
  )
})
