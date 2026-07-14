/**
 * Packed-install smoke test: builds real tarballs for `vaultkeeper` and
 * `@vaultkeeper/cli`, installs them into an isolated temp project the same
 * way an end user would (`npm install <tarball>`), then drives the packages
 * through their public entry points — `npx vaultkeeper --version` and
 * `import('vaultkeeper')`. Unlike packaging.test.ts (which only inspects
 * `npm pack --dry-run` file listings), this test actually installs and runs
 * the packed output, so it catches defects that only manifest once npm's
 * bin-linking and module resolution run for real — the two failure modes
 * from https://github.com/mike-north/vaultkeeper/issues/64:
 *   - contradictory/missing bin ownership ("could not determine executable
 *     to run")
 *   - a `types`/`main`/`exports` path that doesn't exist in the tarball,
 *     which breaks module resolution even though `npm pack --dry-run` may
 *     still succeed
 *
 * Uses `pnpm pack` (not `npm pack`) to produce the installable tarballs
 * because pnpm rewrites `workspace:*` dependency ranges to the real resolved
 * semver version at pack time; `npm pack` would leave the literal string
 * "workspace:*" in the tarball's package.json, which is not installable
 * outside a pnpm workspace.
 */
import { describe, it, expect, afterAll } from 'vitest'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import * as os from 'node:os'
import * as path from 'node:path'
import { fileURLToPath } from 'node:url'

const execFileAsync = promisify(execFile)

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const repoRoot = path.resolve(__dirname, '..', '..', '..', '..')

interface PnpmPackResult {
  // pnpm's `pack --json` output has varied across versions: some emit
  // `filename` (observed as a full path under --pack-destination on the
  // pnpm version pinned in this repo's packageManager field), others emit
  // `tarball` (documented as a basename). Accept either and resolve
  // whichever we get against destDir so this doesn't drift silently.
  filename?: string
  tarball?: string
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return (
    typeof value === 'object' &&
    value !== null &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype &&
    Object.getOwnPropertySymbols(value).length === 0
  )
}

function isPnpmPackResult(value: unknown): value is PnpmPackResult {
  if (!isPlainObject(value)) {
    return false
  }
  if (value.filename !== undefined && typeof value.filename !== 'string') {
    return false
  }
  if (value.tarball !== undefined && typeof value.tarball !== 'string') {
    return false
  }
  return typeof value.filename === 'string' || typeof value.tarball === 'string'
}

interface PackageJsonVersion {
  version: string
}

function isPackageJsonVersion(value: unknown): value is PackageJsonVersion {
  return isPlainObject(value) && typeof value.version === 'string'
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
    throw new Error(
      `pnpm pack output for ${packageDir} had neither filename nor tarball: ${stdout}`,
    )
  }
  // Resolve against destDir in case this pnpm version returned a basename
  // (`tarball`) rather than the full path (`filename`).
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

describe('packed-install smoke test', () => {
  it('installs the packed tarballs and resolves the vaultkeeper bin and library entry point', async () => {
    const packDestination = await makeTempDir('vaultkeeper-pack-')
    const [vaultkeeperTarball, cliTarball] = await Promise.all([
      pnpmPack('vaultkeeper', packDestination),
      pnpmPack('cli', packDestination),
    ])

    const cliPackageJsonRaw = await readFile(
      path.join(repoRoot, 'packages', 'cli', 'package.json'),
      'utf8',
    )
    const cliPackageJson: unknown = JSON.parse(cliPackageJsonRaw)
    if (!isPackageJsonVersion(cliPackageJson)) {
      throw new Error('Could not read @vaultkeeper/cli package.json#version')
    }
    const expectedCliVersion = cliPackageJson.version

    const projectDir = await makeTempDir('vaultkeeper-install-')
    await writeFile(
      path.join(projectDir, 'package.json'),
      JSON.stringify(
        { name: 'vaultkeeper-packed-install-smoke-test', version: '0.0.0', private: true },
        null,
        2,
      ),
    )

    await execFileAsync(
      'npm',
      ['install', '--no-save', '--no-audit', '--no-fund', vaultkeeperTarball, cliTarball],
      {
        cwd: projectDir,
      },
    )

    // --no-install keeps this hermetic: if the local bin link is missing —
    // the exact regression this test guards against — npx must fail rather
    // than silently falling back to fetching `vaultkeeper` from the
    // registry, which would mask the bug (and introduce network flakiness).
    const versionResult = await execFileAsync('npx', ['--no-install', 'vaultkeeper', '--version'], {
      cwd: projectDir,
    })
    expect(versionResult.stdout.trim()).toBe(expectedCliVersion)

    // Asserts only that module resolution succeeds — not on any specific
    // export name — so this doesn't couple a packaging test to the library's
    // runtime API surface. execFileAsync rejects (and fails the test) on a
    // non-zero exit, which `.catch` triggers on import rejection.
    const importResult = await execFileAsync(
      'node',
      [
        '-e',
        "import('vaultkeeper').then(() => console.log('import-ok')).catch((err) => { console.error(err); process.exit(1) })",
      ],
      { cwd: projectDir },
    )
    expect(importResult.stdout.trim()).toBe('import-ok')
  }, 120_000)
})
