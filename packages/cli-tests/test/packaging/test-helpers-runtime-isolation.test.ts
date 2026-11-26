/**
 * Packaging test for issue #311 acceptance criterion 7: asserts
 * `@vaultkeeper/test-helpers` — the home of `PresenceSimulatorBackend`, a
 * presence forger deliberately kept unreachable from production (see
 * `packages/test-helpers/src/presence-simulator-backend.ts`) — appears in no
 * runtime dependency graph anywhere in this monorepo.
 *
 * Two layers, mirroring dependency-closure.test.ts's pattern:
 *
 *  1. A static scan of every `packages/*\/package.json`'s production
 *     `dependencies` field (never `devDependencies`/`peerDependencies`,
 *     which are legitimate places to depend on a test-only package) for a
 *     reference to `@vaultkeeper/test-helpers`.
 *  2. A real `npm install <tarball>` of the base `vaultkeeper` library into
 *     an isolated temp project — the same production-consumer install
 *     dependency-closure.test.ts performs — asserting the installed
 *     `node_modules` tree does not contain `@vaultkeeper/test-helpers`
 *     anywhere, at any depth.
 *
 * See https://github.com/mike-north/vaultkeeper/issues/311 and the accepted
 * shape proposal on https://github.com/mike-north/vaultkeeper/issues/307.
 */
import { describe, it, expect, afterAll } from 'vitest'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { mkdtemp, readdir, readFile, rm, writeFile } from 'node:fs/promises'
import * as os from 'node:os'
import * as path from 'node:path'
import { fileURLToPath } from 'node:url'

const execFileAsync = promisify(execFile)

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const repoRoot = path.resolve(__dirname, '..', '..', '..', '..')

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return (
    typeof value === 'object' &&
    value !== null &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype &&
    Object.getOwnPropertySymbols(value).length === 0
  )
}

interface MinimalPackageJson {
  name: string
  dependencies?: Record<string, string>
}

function isMinimalPackageJson(value: unknown): value is MinimalPackageJson {
  if (!isPlainObject(value) || typeof value.name !== 'string') {
    return false
  }
  if (value.dependencies !== undefined) {
    if (!isPlainObject(value.dependencies)) {
      return false
    }
    if (!Object.values(value.dependencies).every((v) => typeof v === 'string')) {
      return false
    }
  }
  return true
}

interface PnpmPackResult {
  filename?: string
  tarball?: string
}

function isPnpmPackResult(value: unknown): value is PnpmPackResult {
  if (!isPlainObject(value)) return false
  if (value.filename !== undefined && typeof value.filename !== 'string') return false
  if (value.tarball !== undefined && typeof value.tarball !== 'string') return false
  return typeof value.filename === 'string' || typeof value.tarball === 'string'
}

async function pnpmPack(packageDir: string, destDir: string): Promise<string> {
  const cwd = path.join(repoRoot, 'packages', packageDir)
  const { stdout } = await execFileAsync(
    'pnpm',
    ['pack', '--pack-destination', destDir, '--json'],
    { cwd },
  )
  const parsed: unknown = JSON.parse(stdout)
  if (!isPnpmPackResult(parsed)) {
    throw new Error(`Unexpected pnpm pack output for ${packageDir}: ${stdout}`)
  }
  const tarballPath = parsed.filename ?? parsed.tarball
  if (tarballPath === undefined) {
    throw new Error(`pnpm pack output for ${packageDir} had no path: ${stdout}`)
  }
  return path.isAbsolute(tarballPath) ? tarballPath : path.join(destDir, tarballPath)
}

const tempDirs: string[] = []

async function makeTempDir(prefix: string): Promise<string> {
  const dir = await mkdtemp(path.join(os.tmpdir(), prefix))
  tempDirs.push(dir)
  return dir
}

afterAll(async () => {
  await Promise.all(tempDirs.map((dir) => rm(dir, { recursive: true, force: true })))
})

const TEST_HELPERS_PACKAGE_NAME = '@vaultkeeper/test-helpers'

describe('@vaultkeeper/test-helpers — never a runtime dependency', () => {
  it('is absent from the production `dependencies` field of every package in the workspace', async () => {
    const packagesDir = path.join(repoRoot, 'packages')
    const packageDirs = await readdir(packagesDir, { withFileTypes: true })

    const offenders: string[] = []
    for (const entry of packageDirs) {
      if (!entry.isDirectory()) {
        continue
      }
      const packageJsonPath = path.join(packagesDir, entry.name, 'package.json')
      let raw: string
      try {
        raw = await readFile(packageJsonPath, 'utf8')
      } catch {
        continue
      }
      const parsed: unknown = JSON.parse(raw)
      if (!isMinimalPackageJson(parsed)) {
        throw new Error(`Malformed package.json for packages/${entry.name}`)
      }
      if (
        parsed.dependencies !== undefined &&
        Object.prototype.hasOwnProperty.call(parsed.dependencies, TEST_HELPERS_PACKAGE_NAME)
      ) {
        offenders.push(parsed.name)
      }
    }

    expect(
      offenders,
      `${TEST_HELPERS_PACKAGE_NAME} must never appear in a production "dependencies" ` +
        `field — found in: ${offenders.join(', ')}`,
    ).toEqual([])
  })

  it('does not appear in node_modules after a production install of the vaultkeeper library', async () => {
    const packDestination = await makeTempDir('vaultkeeper-test-helpers-isolation-pack-')
    const tarball = await pnpmPack('vaultkeeper', packDestination)

    const projectDir = await makeTempDir('vaultkeeper-test-helpers-isolation-install-')
    await writeFile(
      path.join(projectDir, 'package.json'),
      JSON.stringify(
        { name: 'vaultkeeper-test-helpers-isolation-test', version: '0.0.0', private: true },
        null,
        2,
      ),
    )

    await execFileAsync('npm', ['install', '--no-save', '--no-audit', '--no-fund', tarball], {
      cwd: projectDir,
    })

    const nodeModules = path.join(projectDir, 'node_modules')
    const entries = await readdir(nodeModules, { recursive: true })
    const matches = entries.filter((entry) => entry.includes('test-helpers'))

    expect(
      matches,
      `installed node_modules must not contain @vaultkeeper/test-helpers; found: ${matches.join(', ')}`,
    ).toEqual([])
  }, 120_000)
})
