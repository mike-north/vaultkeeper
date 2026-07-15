/**
 * Dependency-closure tests for the base `vaultkeeper` library.
 *
 * Guards the project invariant (CLAUDE.md: "The only runtime dependency for
 * `vaultkeeper` (TS) is `jose`") against regressions where a plugin-backend
 * SDK leaks back into `dependencies`. Two layers:
 *
 *  1. A static assertion on `packages/vaultkeeper/package.json` — production
 *     `dependencies` is exactly `{ jose }`, and `@1password/sdk` lives in
 *     `peerDependencies` marked optional (never in `dependencies`).
 *  2. A real `npm install <tarball>` into an isolated temp project, asserting
 *     the installed dependency closure contains `jose` and does NOT pull
 *     `@1password/sdk` / `@1password/sdk-core`.
 *
 * See https://github.com/mike-north/vaultkeeper/issues/113.
 *
 * Uses `pnpm pack` (not `npm pack`) for the same reason as
 * packed-install.test.ts: pnpm rewrites `workspace:*` ranges to real semver at
 * pack time. `npm install` (not pnpm) performs the consumer-side install so
 * that npm's default behavior around optional peer dependencies — it does NOT
 * auto-install them — is what the test exercises.
 */
import { describe, it, expect, afterAll } from 'vitest'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises'
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

interface VaultkeeperManifest {
  dependencies?: Record<string, string>
  peerDependencies?: Record<string, string>
  peerDependenciesMeta?: Record<string, { optional?: boolean }>
}

function isStringRecord(value: unknown): value is Record<string, string> {
  return isPlainObject(value) && Object.values(value).every((v) => typeof v === 'string')
}

function isVaultkeeperManifest(value: unknown): value is VaultkeeperManifest {
  if (!isPlainObject(value)) return false
  if (value.dependencies !== undefined && !isStringRecord(value.dependencies)) return false
  if (value.peerDependencies !== undefined && !isStringRecord(value.peerDependencies)) return false
  if (
    value.peerDependenciesMeta !== undefined &&
    !(
      isPlainObject(value.peerDependenciesMeta) &&
      Object.values(value.peerDependenciesMeta).every(
        (v) => isPlainObject(v) && (v.optional === undefined || typeof v.optional === 'boolean'),
      )
    )
  ) {
    return false
  }
  return true
}

async function readVaultkeeperManifest(): Promise<VaultkeeperManifest> {
  const raw = await readFile(path.join(repoRoot, 'packages', 'vaultkeeper', 'package.json'), 'utf8')
  const parsed: unknown = JSON.parse(raw)
  if (!isVaultkeeperManifest(parsed)) {
    throw new Error('Malformed packages/vaultkeeper/package.json')
  }
  return parsed
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

describe('vaultkeeper dependency closure', () => {
  it('declares exactly one production dependency (jose)', async () => {
    const pkg = await readVaultkeeperManifest()
    // CLAUDE.md invariant: jose is the ONLY runtime dependency.
    expect(Object.keys(pkg.dependencies ?? {})).toEqual(['jose'])
  })

  it('keeps @1password/sdk out of dependencies and as an optional peer', async () => {
    const pkg = await readVaultkeeperManifest()
    expect(pkg.dependencies ?? {}).not.toHaveProperty('@1password/sdk')
    expect(pkg.peerDependencies ?? {}).toHaveProperty('@1password/sdk')
    expect(pkg.peerDependenciesMeta?.['@1password/sdk']?.optional).toBe(true)
  })

  it('does not pull @1password/sdk into node_modules on a default install', async () => {
    const packDestination = await makeTempDir('vaultkeeper-closure-pack-')
    const tarball = await pnpmPack('vaultkeeper', packDestination)

    const projectDir = await makeTempDir('vaultkeeper-closure-install-')
    await writeFile(
      path.join(projectDir, 'package.json'),
      JSON.stringify(
        { name: 'vaultkeeper-closure-test', version: '0.0.0', private: true },
        null,
        2,
      ),
    )

    await execFileAsync('npm', ['install', '--no-save', '--no-audit', '--no-fund', tarball], {
      cwd: projectDir,
    })

    const nodeModules = path.join(projectDir, 'node_modules')
    const topLevel = await readdir(nodeModules)

    // jose is the sole runtime dependency and must be present.
    expect(topLevel).toContain('jose')

    // The 1Password SDKs are optional peers — npm must not auto-install them.
    expect(topLevel).not.toContain('@1password')
    const scoped = topLevel.includes('@1password')
      ? await readdir(path.join(nodeModules, '@1password'))
      : []
    expect(scoped).not.toContain('sdk')
    expect(scoped).not.toContain('sdk-core')
  }, 120_000)
})
