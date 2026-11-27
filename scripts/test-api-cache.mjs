/** Exercises API documentation generation with extraction outputs restored by Nx. */
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { cpSync, existsSync, mkdtempSync, readFileSync, rmSync, symlinkSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { basename, join, resolve } from 'node:path'
import { test } from 'node:test'

const packages = ['vaultkeeper', 'test-helpers', 'vaultkeeper-wasm', 'cli', 'cli-test-helpers']
const projects = [
  'vaultkeeper',
  '@vaultkeeper/test-helpers',
  '@vaultkeeper/wasm',
  '@vaultkeeper/cli',
  '@vaultkeeper/cli-test-helpers',
]

test('cached extraction restores documentation models for both docs workflows', () => {
  const source = process.cwd()
  const scratch = mkdtempSync(join(tmpdir(), 'vaultkeeper-api-cache-'))
  const workspace = join(scratch, 'workspace')
  try {
    // Isolate all generated files and preserve the installed dependencies for the subprocesses.
    cpSync(source, workspace, {
      recursive: true,
      filter: (path) =>
        !['.git', '.nx', 'node_modules', 'target', 'dist', 'tmp', 'scratch'].includes(
          basename(path),
        ),
    })
    for (const root of [
      '',
      ...packages.map((pkg) => join('packages', pkg)),
      join('packages', 'cli-tests'),
    ]) {
      const modules = join(source, root, 'node_modules')
      if (existsSync(modules)) {
        cpSync(modules, join(workspace, root, 'node_modules'), {
          recursive: true,
          verbatimSymlinks: true,
          filter: (path) => path !== join(source, 'node_modules', '.pnpm'),
        })
      }
    }
    symlinkSync(
      join(source, 'node_modules', '.pnpm'),
      join(workspace, 'node_modules', '.pnpm'),
      'dir',
    )
    const env = {
      ...process.env,
      NX_CACHE_DIRECTORY: join(scratch, 'cache'),
      NX_DAEMON: 'false',
      NX_TUI: 'false',
      FORCE_COLOR: '0',
    }
    const run = (script) =>
      execFileSync('pnpm', [script], {
        cwd: workspace,
        encoding: 'utf8',
        env,
        stdio: ['ignore', 'pipe', 'pipe'],
      })
    const model = (pkg) =>
      join(
        workspace,
        'packages',
        pkg,
        'tmp/api-extractor',
        `${pkg === 'vaultkeeper-wasm' ? 'wasm' : pkg}.api.json`,
      )
    const assertCached = (output, target) => {
      for (const project of projects) {
        assert.ok(
          output.includes(`nx run ${project}:"${target}"  [local cache]`),
          `${project}:${target} did not hit cache`,
        )
      }
    }
    run('build')
    for (const target of ['check:api-report', 'generate:api-report']) {
      run(target)
      const expected = packages.map((pkg) => readFileSync(model(pkg)))
      for (const pkg of packages) rmSync(model(pkg))
      assertCached(run(target), target)
      packages.forEach((pkg, index) => assert.deepEqual(readFileSync(model(pkg)), expected[index]))
      run('check:api-docs')
    }
    for (const pkg of packages) rmSync(model(pkg))
    assertCached(run('generate:api-docs'), 'generate:api-report')
    run('check:api-docs')
  } finally {
    rmSync(resolve(scratch), { recursive: true, force: true })
  }
})
