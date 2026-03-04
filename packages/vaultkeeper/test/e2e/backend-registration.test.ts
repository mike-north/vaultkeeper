/**
 * End-to-end test verifying that built-in backends are registered when
 * vaultkeeper is consumed as an external dependency.
 *
 * Uses `fixturify-project` to create an isolated consumer project outside the
 * monorepo, ensuring we test the published package shape — not internal module
 * resolution within the source tree.
 *
 * @see https://github.com/mike-north/vaultkeeper/issues/21
 */

import { describe, it, expect, afterEach } from 'vitest'
import { Project } from 'fixturify-project'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { resolve, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const execFileAsync = promisify(execFile)
const __dirname = dirname(fileURLToPath(import.meta.url))

describe('built-in backend registration (issue #21, external consumer)', () => {
  let project: Project | undefined

  afterEach(() => {
    project?.dispose()
    project = undefined
  })

  it('should register all built-in backends when imported from a consumer project', async () => {
    project = new Project('vaultkeeper-consumer', '1.0.0')
    project.mergeFiles({
      'package.json': JSON.stringify({
        name: 'vaultkeeper-consumer',
        version: '1.0.0',
        type: 'module',
      }),
      'check-backends.mjs': [
        `import { BackendRegistry } from 'vaultkeeper';`,
        `const types = BackendRegistry.getTypes();`,
        `const expected = ['file', 'keychain', 'dpapi', 'secret-tool', '1password', 'yubikey'];`,
        `const missing = expected.filter(t => !types.includes(t));`,
        `if (missing.length > 0) {`,
        `  console.error('Missing backends:', missing.join(', '));`,
        `  console.error('Registered:', types.join(', '));`,
        `  process.exit(1);`,
        `}`,
        `console.log(JSON.stringify(types.sort()));`,
      ].join('\n'),
    })

    // Link local vaultkeeper build
    const vaultkeeperRoot = resolve(__dirname, '..', '..')
    project.linkDependency('vaultkeeper', { target: vaultkeeperRoot })

    await project.write()

    // Requires `pnpm build` to have run so that dist/ exists for the symlink
    const { stdout } = await execFileAsync('node', ['check-backends.mjs'], {
      cwd: project.baseDir,
      timeout: 10_000,
    })

    const types: unknown = JSON.parse(stdout.trim())
    expect(Array.isArray(types)).toBe(true)
    expect(types).toContain('file')
    expect(types).toContain('keychain')
    expect(types).toContain('dpapi')
    expect(types).toContain('secret-tool')
    expect(types).toContain('1password')
    expect(types).toContain('yubikey')
  })
})
