/**
 * End-to-end test verifying that the published `.d.ts` of vaultkeeper's
 * public packages (`vaultkeeper`, `@vaultkeeper/test-helpers`,
 * `@vaultkeeper/cli-test-helpers`) typechecks in a standard strict consumer
 * project across a matrix of pinned TypeScript compiler versions — without
 * the consumer adding an explicit `"types": ["node"]` override to their
 * tsconfig.
 *
 * `SecretAccessor.read()`, `SignRequest.data`, and `VerifyRequest.data`
 * reference `Buffer`. Before the fix for #72, the rollup relied on the
 * ambient global `Buffer` type. Confirmed against a real `npm pack` + `npm
 * install` consumer (not just this fixture harness): with a strict NodeNext
 * tsconfig that sets `"types": []` — the common pattern in monorepo
 * boilerplates that scope ambient globals explicitly rather than
 * auto-including every `@types/*` package — the pre-fix rollup fails with
 * `TS2591: Cannot find name 'Buffer'` even though `@types/node` is
 * installed, and adding `"node"` to `types` (the documented workaround) or
 * applying this fix both resolve it. This test packs the real published
 * shape (via a linked build, not source-internal module resolution) and
 * typechecks a consumer file against it under that same `"types": []`
 * condition.
 *
 * The stated TypeScript-version support range in both READMEs
 * (`README.md`, `packages/vaultkeeper/README.md`) is derived from this
 * matrix, not guessed (#125). If a pinned version here changes or a cell
 * starts failing, update the README range to match — see the matrix result
 * summary in that issue's PR.
 *
 * Uses `fixturify-project` to create an isolated consumer project outside
 * the monorepo, matching the pattern in `backend-registration.test.ts`.
 *
 * Requires `pnpm build` to have run for `vaultkeeper`, `@vaultkeeper/test-helpers`,
 * and `@vaultkeeper/cli-test-helpers`, and requires the pinned TypeScript
 * compilers in `./ts-version-fixtures` to have been installed via
 * `pnpm --dir packages/vaultkeeper/test/e2e/ts-version-fixtures install --ignore-workspace`
 * (see that directory's `package.json` for why it's a standalone,
 * non-workspace install). Matrix cells for which the pinned compiler isn't
 * installed are registered as real Vitest skips via `it.skipIf` (mirroring
 * the conformance runner's `describe.skipIf` pattern) — not a silent early
 * `return`, which Vitest would otherwise report as a false pass — so local
 * runs without that setup step show honest "skipped" cells instead of
 * misleadingly green ones.
 *
 * That skip is outside-CI only. Both `ci.yml` and `release.yml` install the
 * fixtures before running `pnpm test`, so inside CI (`process.env.CI` set) a
 * missing pinned compiler is never treated as a skip — the cell still runs
 * and fails with a remediation message naming the install command. This
 * means a future workflow refactor that drops or reorders the install step
 * is caught by a failing test rather than silently turning this gate off
 * (#136). See `ts-version-matrix-gate.ts` for the extracted skip/fail
 * predicate and `test/unit/ts-version-matrix-gate.test.ts` for its coverage.
 *
 * @see https://github.com/mike-north/vaultkeeper/issues/72
 * @see https://github.com/mike-north/vaultkeeper/issues/125
 * @see https://github.com/mike-north/vaultkeeper/issues/136
 */

import { describe, it, expect, afterEach } from 'vitest'
import { Project } from 'fixturify-project'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { createRequire } from 'node:module'
import { resolve, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { shouldSkipMatrixCell, missingCompilerMessage } from './ts-version-matrix-gate.js'

const execFileAsync = promisify(execFile)
const __dirname = dirname(fileURLToPath(import.meta.url))
const require = createRequire(import.meta.url)

const fixturesRoot = resolve(__dirname, 'ts-version-fixtures')

/** Resolves the installed root of a pinned compiler, or undefined if the standalone fixtures install hasn't been run. */
function resolveFixtureTypescriptRoot(packageAlias: string): string | undefined {
  try {
    return dirname(require.resolve(`${packageAlias}/package.json`, { paths: [fixturesRoot] }))
  } catch {
    return undefined
  }
}

/**
 * Pinned TypeScript compiler versions typechecked against the shipped
 * `.d.ts`. Chosen per #125's acceptance criteria: the stated floor
 * (5.0.x), the latest 5.x, and the latest 6.x/7.x (to establish whether
 * newer majors work). Update alongside `./ts-version-fixtures/package.json`
 * and the README TypeScript-version note if this list changes.
 *
 * `typescriptRoot` is resolved once at module load (a synchronous
 * `require.resolve`), not inside the test body, so `it.skipIf` below can
 * make a real skip/run decision per cell before Vitest registers the test.
 *
 * TODO(#136): optional hardening — assert each resolved compiler's real
 * `<typescriptRoot>/package.json` version matches its pin here, so these
 * labels and the READMEs' "5.0.4-7.0.2" claim are verified rather than
 * assumed. Deferred: not required by #136's acceptance criteria.
 */
const TS_VERSIONS = [
  { label: 'TypeScript 5.0.4 (stated floor)', packageAlias: 'typescript-5-0' },
  { label: 'TypeScript 5.9.3 (latest 5.x)', packageAlias: 'typescript-5-9' },
  { label: 'TypeScript 6.0.3 (latest 6.x)', packageAlias: 'typescript-6-0' },
  { label: 'TypeScript 7.0.2 (latest 7.x)', packageAlias: 'typescript-7-0' },
].map((entry) => ({ ...entry, typescriptRoot: resolveFixtureTypescriptRoot(entry.packageAlias) }))

const consumerSource = [
  `import type { SecretAccessor, SignRequest, VerifyRequest } from 'vaultkeeper'`,
  `import { TestVault } from '@vaultkeeper/test-helpers'`,
  `import { createCliTestEnv } from '@vaultkeeper/cli-test-helpers'`,
  ``,
  `function useAccessor(accessor: SecretAccessor): void {`,
  `  accessor.read((buf) => {`,
  `    buf.toString('utf8')`,
  `  })`,
  `}`,
  ``,
  // Issue #168: read() passes the callback's return value through, so the
  // consumer can capture a caller-derived value. This annotation fails to
  // compile if read()'s return type regresses to `void` (TS2322).
  `function useAccessorReturn(accessor: SecretAccessor): string {`,
  `  return accessor.read((buf) => buf.toString('utf8'))`,
  `}`,
  ``,
  // The generic return type must be inferred from the callback, not widened to
  // a fixed type — deriving a number flows out as a number.
  `function useAccessorReturnNumber(accessor: SecretAccessor): number {`,
  `  return accessor.read((buf) => buf.length)`,
  `}`,
  ``,
  `function useSignRequest(req: SignRequest): string | Buffer {`,
  `  return req.data`,
  `}`,
  ``,
  `function useVerifyRequest(req: VerifyRequest): string | Buffer {`,
  `  return req.data`,
  `}`,
  ``,
  `async function useTestVault(): Promise<TestVault> {`,
  `  return TestVault.create()`,
  `}`,
  ``,
  `async function useCliTestEnv(): Promise<void> {`,
  `  const env = await createCliTestEnv()`,
  `  await env.cleanup()`,
  `}`,
  ``,
  `export { useAccessor, useAccessorReturn, useAccessorReturnNumber, useSignRequest, useVerifyRequest, useTestVault, useCliTestEnv }`,
].join('\n')

// `process.env.CI` is read once at module load, matching how
// `typescriptRoot` is resolved for TS_VERSIONS above — both are per-run
// facts, not per-test state.
const inCI = process.env.CI !== undefined

describe('published .d.ts typechecks across the supported TypeScript version matrix (issue #125)', () => {
  let project: Project | undefined

  afterEach(() => {
    project?.dispose()
    project = undefined
  })

  for (const { label, typescriptRoot } of TS_VERSIONS) {
    // A real vitest skip (registers the cell as "skipped" in the report),
    // not a silent early `return` from inside the test body — an early
    // `return` would still report the cell as passed, which is misleading
    // when the pinned compiler was never actually invoked. Mirrors the
    // conformance runner's `describe.skipIf` pattern for an unavailable
    // dependency.
    //
    // Outside CI this skips cleanly when the fixtures haven't been
    // installed locally. Inside CI it never skips: a missing compiler there
    // means the fixtures-install workflow step regressed, so the cell must
    // run and fail rather than silently disappear (#136).
    it.skipIf(shouldSkipMatrixCell(typescriptRoot, inCI))(
      `typechecks under ${label}`,
      async () => {
        // Only reachable without a resolved compiler when running in CI —
        // shouldSkipMatrixCell would have skipped this cell otherwise.
        if (!typescriptRoot) {
          throw new Error(missingCompilerMessage(label))
        }

        project = new Project('vaultkeeper-dts-consumer', '1.0.0')
        project.mergeFiles({
          'package.json': JSON.stringify({
            name: 'vaultkeeper-dts-consumer',
            version: '1.0.0',
            type: 'module',
          }),
          'tsconfig.json': JSON.stringify({
            compilerOptions: {
              target: 'ES2022',
              module: 'NodeNext',
              moduleResolution: 'NodeNext',
              strict: true,
              skipLibCheck: false,
              noEmit: true,
              // Deliberately scopes ambient globals to none, as many strict
              // monorepo tsconfigs do. This is the reliably reproducible
              // trigger verified for issue #72 (the issue's literal "no
              // types array" setup doesn't reproduce on TS 5.9; explicit
              // types: [] does): `@types/node` is installed (linked below)
              // but not auto-included, so the published `.d.ts` must
              // resolve `Buffer` via a real import rather than relying on
              // the ambient global.
              types: [],
            },
            include: ['consumer.ts'],
          }),
          'consumer.ts': consumerSource,
        })

        // Link the local builds (requires `pnpm build` to have run for
        // these three packages).
        const vaultkeeperRoot = resolve(__dirname, '..', '..')
        const testHelpersRoot = resolve(__dirname, '..', '..', '..', 'test-helpers')
        const cliTestHelpersRoot = resolve(__dirname, '..', '..', '..', 'cli-test-helpers')
        project.linkDependency('vaultkeeper', { target: vaultkeeperRoot })
        project.linkDependency('@vaultkeeper/test-helpers', { target: testHelpersRoot })
        project.linkDependency('@vaultkeeper/cli-test-helpers', { target: cliTestHelpersRoot })

        // Link the pinned compiler for this matrix cell.
        project.linkDependency('typescript', { target: typescriptRoot })

        // Link the monorepo's own @types/node so every cell typechecks
        // against the same lib files, without a network install.
        const typesNodeRoot = dirname(require.resolve('@types/node/package.json'))
        project.linkDependency('@types/node', { target: typesNodeRoot })

        await project.write()

        const tscBin = resolve(typescriptRoot, 'bin', 'tsc')

        // A real tsc invocation (loading the compiler, @types/node's lib
        // files, and the vaultkeeper rollup) is slow on CI runners relative
        // to vitest's 5s default test timeout, so both the test and the
        // child process get a generous budget here.
        await expect(
          execFileAsync('node', [tscBin, '--noEmit'], {
            cwd: project.baseDir,
            timeout: 90_000,
          }),
        ).resolves.toBeDefined()
      },
      120_000,
    )
  }
})
