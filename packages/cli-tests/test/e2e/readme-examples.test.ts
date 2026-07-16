/**
 * README example drift guard (issue #217): the fenced examples in every shipped
 * README are validated against the *built* packages, so an example that no
 * longer works fails CI instead of a fresh user.
 *
 * - Shell fences in the CLI + root README are executed verbatim in an isolated
 *   `file`-backend environment and must exit 0.
 * - TS/JS fences in the two library READMEs are type-checked against the built
 *   `.d.ts` and must compile clean.
 *
 * The proving case for issue #214 is the CLI README's sign/verify walkthrough:
 * it reproduces the shell newline mismatch (`printf '%s'` vs `<<<`) that made
 * the documented sequence fail, so this test fails against the pre-fix README
 * and passes against the corrected one.
 *
 * See {@link ./readme-example-harness.ts} for the extraction/execution/type-check
 * machinery and the documented `readme-example: skip` opt-out marker.
 *
 * @see https://github.com/mike-north/vaultkeeper/issues/217
 * @see https://github.com/mike-north/vaultkeeper/issues/214
 */
import { readFileSync } from 'node:fs'
import * as path from 'node:path'
import { describe, it, expect } from 'vitest'
import {
  REPO_ROOT,
  extractFences,
  isShellFence,
  isCodeFence,
  isInstallOnlyFence,
  runShellFence,
  typecheckCodeFence,
  type Fence,
} from './readme-example-harness.js'

/** READMEs whose shell fences are executed. */
const EXEC_READMES = ['packages/cli/README.md', 'README.md']
/** READMEs whose TS/JS fences are type-checked. */
const TYPECHECK_READMES = ['packages/vaultkeeper/README.md', 'packages/vaultkeeper-wasm/README.md']

function fencesFor(readme: string): Fence[] {
  return extractFences(readFileSync(path.join(REPO_ROOT, readme), 'utf8'), readme)
}

const EXEC_FENCES = EXEC_READMES.flatMap(fencesFor).filter(isShellFence)
const TYPECHECK_FENCES = TYPECHECK_READMES.flatMap(fencesFor).filter(isCodeFence)

/** A fence is a sign/verify walkthrough if it drives both `sign` and `verify`. */
function isSignVerifyFence(fence: Fence): boolean {
  return /vaultkeeper sign\b/.test(fence.code) && /vaultkeeper verify\b/.test(fence.code)
}

describe('README shell examples run clean against the built CLI', () => {
  for (const fence of EXEC_FENCES) {
    const id = `${fence.readme}:${String(fence.startLine)}`
    if (fence.skipped) {
      it.skip(`${id} (opted out${fence.skipReason !== undefined ? `: ${fence.skipReason}` : ''})`, () => { /* opted out */ })
      continue
    }
    if (isInstallOnlyFence(fence)) {
      it.skip(`${id} (install-only, needs network)`, () => { /* opted out */ })
      continue
    }
    it(`${id} exits 0`, () => {
      const result = runShellFence(fence)
      expect(
        result.exitCode,
        `\`${fence.readme}\` fence at line ${String(fence.startLine)} exited ${String(result.exitCode)}.\n` +
          `--- stdout ---\n${result.stdout}\n--- stderr ---\n${result.stderr}`,
      ).toBe(0)
    })
  }
})

describe('README TypeScript/JavaScript examples type-check against the built types', () => {
  for (const fence of TYPECHECK_FENCES) {
    const id = `${fence.readme}:${String(fence.startLine)}`
    if (fence.skipped) {
      it.skip(`${id} (opted out${fence.skipReason !== undefined ? `: ${fence.skipReason}` : ''})`, () => { /* opted out */ })
      continue
    }
    it(`${id} (${fence.lang}) compiles`, () => {
      const result = typecheckCodeFence(fence)
      expect(
        result.exitCode,
        `\`${fence.readme}\` ${fence.lang} fence at line ${String(fence.startLine)} did not type-check:\n${result.output}`,
      ).toBe(0)
    })
  }
})

describe('coverage guards (non-vacuous)', () => {
  it('finds shell fences to execute and TS/JS fences to type-check', () => {
    // Guard against a parser regression that silently matches nothing, which
    // would make every check vacuously pass.
    expect(EXEC_FENCES.some((f) => !f.skipped && !isInstallOnlyFence(f))).toBe(true)
    expect(TYPECHECK_FENCES.some((f) => !f.skipped)).toBe(true)
  })

  it('executes the sign/verify walkthrough as the #214 proving case', () => {
    // The CLI README's sign/verify walkthrough must be a real, executed fence —
    // not skipped or install-only — so this suite genuinely reproduces #214.
    const signVerify = EXEC_FENCES.filter(
      (f) => f.readme === 'packages/cli/README.md' && isSignVerifyFence(f),
    )
    expect(signVerify.length).toBeGreaterThan(0)
    for (const fence of signVerify) {
      expect(fence.skipped, 'the sign/verify walkthrough must not be opted out').toBe(false)
      expect(isInstallOnlyFence(fence)).toBe(false)
    }
  })

  it('type-checks a quick-start fence in each library README', () => {
    for (const readme of TYPECHECK_READMES) {
      expect(
        TYPECHECK_FENCES.some((f) => f.readme === readme && !f.skipped),
        `${readme} should have at least one type-checked fence`,
      ).toBe(true)
    }
  })
})

describe('harness: fence extraction and classification', () => {
  it('records a skip marker (and its reason) on the immediately preceding line', () => {
    const md = ['<!-- readme-example: skip - references an earlier vault -->', '```ts', 'await vault.x()', '```'].join(
      '\n',
    )
    const [fence] = extractFences(md, 'X.md')
    expect(fence?.skipped).toBe(true)
    expect(fence?.skipReason).toBe('references an earlier vault')
  })

  it('detects a skip marker across intervening blank lines', () => {
    const md = ['<!-- readme-example: skip -->', '', '```sh', 'vaultkeeper exec ...', '```'].join('\n')
    const [fence] = extractFences(md, 'X.md')
    expect(fence?.skipped).toBe(true)
    expect(fence?.skipReason).toBeUndefined()
  })

  it('does not treat an ordinary fence as skipped', () => {
    const md = ['Some prose.', '```sh', 'vaultkeeper doctor', '```'].join('\n')
    const [fence] = extractFences(md, 'X.md')
    expect(fence?.skipped).toBe(false)
  })

  it('auto-skips an install-only fence but not a real command sequence', () => {
    const [install] = extractFences(['```sh', 'pnpm add -g @vaultkeeper/cli', '```'].join('\n'), 'X.md')
    expect(install && isInstallOnlyFence(install)).toBe(true)
    const [run] = extractFences(['```sh', '# install first', 'vaultkeeper doctor', '```'].join('\n'), 'X.md')
    expect(run && isInstallOnlyFence(run)).toBe(false)
  })

  it('classifies fence languages', () => {
    const fences = extractFences(
      ['```sh', 'x', '```', '```ts', 'y', '```', '```json', 'z', '```'].join('\n'),
      'X.md',
    )
    expect(fences.filter(isShellFence).map((f) => f.lang)).toEqual(['sh'])
    expect(fences.filter(isCodeFence).map((f) => f.lang)).toEqual(['ts'])
  })
})
