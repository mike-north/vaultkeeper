/**
 * End-to-end test verifying that the published `.d.ts` typechecks in a
 * standard strict consumer project — without the consumer adding an
 * explicit `"types": ["node"]` override to their tsconfig.
 *
 * `SecretAccessor.read()`, `SignRequest.data`, and `VerifyRequest.data`
 * reference `Buffer`. Before the fix, the rollup relied on the ambient
 * global `Buffer` type. Confirmed against a real `npm pack` + `npm install`
 * consumer (not just this fixture harness): with a strict NodeNext tsconfig
 * that sets `"types": []` — the common pattern in monorepo boilerplates that
 * scope ambient globals explicitly rather than auto-including every
 * `@types/*` package — the pre-fix rollup fails with `TS2591: Cannot find
 * name 'Buffer'` even though `@types/node` is installed, and adding
 * `"node"` to `types` (the documented workaround) or applying this fix both
 * resolve it. This test packs the real published shape (via a linked
 * build, not source-internal module resolution) and typechecks a consumer
 * file against it under that same `"types": []` condition.
 *
 * Uses `fixturify-project` to create an isolated consumer project outside
 * the monorepo, matching the pattern in `backend-registration.test.ts`.
 *
 * @see https://github.com/mike-north/vaultkeeper/issues/72
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

describe('published .d.ts typechecks Buffer-typed API in strict consumers (issue #72)', () => {
  let project: Project | undefined

  afterEach(() => {
    project?.dispose()
    project = undefined
  })

  it('should typecheck when the consumer scopes ambient globals with "types": []', async () => {
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
          // monorepo tsconfigs do. This is the exact reproduction from
          // issue #72: `@types/node` is installed (linked below) but not
          // auto-included, so the published `.d.ts` must resolve `Buffer`
          // via a real import rather than relying on the ambient global.
          types: [],
        },
        include: ['consumer.ts'],
      }),
      'consumer.ts': [
        `import type { SecretAccessor, SignRequest, VerifyRequest } from 'vaultkeeper'`,
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
        `export { useAccessor, useSignRequest, useVerifyRequest }`,
      ].join('\n'),
    })

    // Link the local vaultkeeper build (requires `pnpm build` to have run).
    const vaultkeeperRoot = resolve(__dirname, '..', '..')
    project.linkDependency('vaultkeeper', { target: vaultkeeperRoot })

    // Link the monorepo's own typescript and @types/node so the consumer
    // project typechecks with the same compiler/lib versions as CI, without
    // a network install.
    const typescriptRoot = dirname(require.resolve('typescript/package.json'))
    project.linkDependency('typescript', { target: typescriptRoot })

    const typesNodeRoot = dirname(require.resolve('@types/node/package.json'))
    project.linkDependency('@types/node', { target: typesNodeRoot })

    await project.write()

    const tscBin = resolve(typescriptRoot, 'bin', 'tsc')

    await expect(
      execFileAsync('node', [tscBin, '--noEmit'], {
        cwd: project.baseDir,
        timeout: 30_000,
      }),
    ).resolves.toBeDefined()
  })
})
