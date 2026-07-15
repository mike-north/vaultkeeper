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
 * installed are skipped, not failed, so local runs without that setup step
 * still pass; CI always installs the fixtures first.
 *
 * @see https://github.com/mike-north/vaultkeeper/issues/72
 * @see https://github.com/mike-north/vaultkeeper/issues/125
 */

import { describe, it, expect, afterEach } from 'vitest'
import { Project } from 'fixturify-project'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { createRequire } from 'node:module'
import { resolve, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const execFileAsync = promisify(execFile)
const __dirname = dirname(fileURLToPath(import.meta.url))
const require = createRequire(import.meta.url)

/**
 * Pinned TypeScript compiler versions typechecked against the shipped
 * `.d.ts`. Chosen per #125's acceptance criteria: the stated floor
 * (5.0.x), the latest 5.x, and the latest 6.x/7.x (to establish whether
 * newer majors work). Update alongside `./ts-version-fixtures/package.json`
 * and the README TypeScript-version note if this list changes.
 */
const TS_VERSIONS = [
  { label: 'TypeScript 5.0.4 (stated floor)', packageAlias: 'typescript-5-0' },
  { label: 'TypeScript 5.9.3 (latest 5.x)', packageAlias: 'typescript-5-9' },
  { label: 'TypeScript 6.0.3 (latest 6.x)', packageAlias: 'typescript-6-0' },
  { label: 'TypeScript 7.0.2 (latest 7.x)', packageAlias: 'typescript-7-0' },
] as const

const fixturesRoot = resolve(__dirname, 'ts-version-fixtures')

/** Resolves the installed root of a pinned compiler, or undefined if the standalone fixtures install hasn't been run. */
function resolveFixtureTypescriptRoot(packageAlias: string): string | undefined {
  try {
    return dirname(require.resolve(`${packageAlias}/package.json`, { paths: [fixturesRoot] }))
  } catch {
    return undefined
  }
}

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
  `export { useAccessor, useSignRequest, useVerifyRequest, useTestVault, useCliTestEnv }`,
].join('\n')

describe('published .d.ts typechecks across the supported TypeScript version matrix (issue #125)', () => {
  let project: Project | undefined

  afterEach(() => {
    project?.dispose()
    project = undefined
  })

  it.each(TS_VERSIONS)(
    'typechecks under $label',
    async ({ packageAlias, label }) => {
      const typescriptRoot = resolveFixtureTypescriptRoot(packageAlias)
      if (!typescriptRoot) {
        console.warn(
          `Skipping "${label}": pinned compiler "${packageAlias}" isn't installed. ` +
            `Run: pnpm --dir packages/vaultkeeper/test/e2e/ts-version-fixtures install --ignore-workspace`,
        )
        return
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
            // trigger verified for issue #72 (the issue's literal "no types
            // array" setup doesn't reproduce on TS 5.9; explicit types: []
            // does): `@types/node` is installed (linked below) but not
            // auto-included, so the published `.d.ts` must resolve `Buffer`
            // via a real import rather than relying on the ambient global.
            types: [],
          },
          include: ['consumer.ts'],
        }),
        'consumer.ts': consumerSource,
      })

      // Link the local builds (requires `pnpm build` to have run for these
      // three packages).
      const vaultkeeperRoot = resolve(__dirname, '..', '..')
      const testHelpersRoot = resolve(__dirname, '..', '..', '..', 'test-helpers')
      const cliTestHelpersRoot = resolve(__dirname, '..', '..', '..', 'cli-test-helpers')
      project.linkDependency('vaultkeeper', { target: vaultkeeperRoot })
      project.linkDependency('@vaultkeeper/test-helpers', { target: testHelpersRoot })
      project.linkDependency('@vaultkeeper/cli-test-helpers', { target: cliTestHelpersRoot })

      // Link the pinned compiler for this matrix cell.
      project.linkDependency('typescript', { target: typescriptRoot })

      // Link the monorepo's own @types/node so every cell typechecks against
      // the same lib files, without a network install.
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
})
