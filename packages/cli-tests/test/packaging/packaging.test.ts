/**
 * Packaging tests for every publishable package: asserts that `npm pack` would
 * include a README.md and that package.json carries repository/homepage/bugs
 * metadata. See https://github.com/mike-north/vaultkeeper/issues/63.
 *
 * Uses `npm pack --dry-run --json` specifically because it is the tool that
 * simulates the registry's tarball-inclusion rules (README/LICENSE are always
 * included regardless of the `files` field) — pnpm has no dry-run equivalent.
 * This does not install or run anything from the npm registry.
 */
import { describe, it, expect } from 'vitest'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { readFile } from 'node:fs/promises'
import * as path from 'node:path'
import { fileURLToPath } from 'node:url'

const execFileAsync = promisify(execFile)

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const repoRoot = path.resolve(__dirname, '..', '..', '..', '..')

interface NpmPackFileEntry {
  path: string
}

interface NpmPackResult {
  files: NpmPackFileEntry[]
}

interface RepositoryField {
  type: string
  url: string
  directory?: string
}

interface PackageJson {
  name: string
  homepage?: string
  bugs?: string
  repository?: RepositoryField | string
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

function isNpmPackFileEntry(value: unknown): value is NpmPackFileEntry {
  return isPlainObject(value) && typeof value.path === 'string'
}

function isNpmPackResult(value: unknown): value is NpmPackResult {
  return isPlainObject(value) && Array.isArray(value.files) && value.files.every(isNpmPackFileEntry)
}

function isRepositoryField(value: unknown): value is RepositoryField {
  return (
    isPlainObject(value) &&
    typeof value.type === 'string' &&
    typeof value.url === 'string' &&
    (value.directory === undefined || typeof value.directory === 'string')
  )
}

function isPackageJson(value: unknown): value is PackageJson {
  if (!isPlainObject(value)) {
    return false
  }
  if (typeof value.name !== 'string') {
    return false
  }
  if (value.homepage !== undefined && typeof value.homepage !== 'string') {
    return false
  }
  if (value.bugs !== undefined && typeof value.bugs !== 'string') {
    return false
  }
  if (
    value.repository !== undefined &&
    typeof value.repository !== 'string' &&
    !isRepositoryField(value.repository)
  ) {
    return false
  }
  return true
}

const publishablePackageDirs = [
  'vaultkeeper',
  'cli',
  'vaultkeeper-wasm',
  'test-helpers',
  'cli-test-helpers',
]

async function readPackageJson(packageDir: string): Promise<PackageJson> {
  const raw = await readFile(path.join(repoRoot, 'packages', packageDir, 'package.json'), 'utf8')
  const parsed: unknown = JSON.parse(raw)
  if (!isPackageJson(parsed)) {
    throw new Error(`Malformed package.json for ${packageDir}`)
  }
  return parsed
}

async function runNpmPackDryRun(packageDir: string): Promise<NpmPackResult> {
  const cwd = path.join(repoRoot, 'packages', packageDir)
  const { stdout } = await execFileAsync('npm', ['pack', '--dry-run', '--json'], { cwd })
  const parsed: unknown = JSON.parse(stdout)
  const first: unknown = Array.isArray(parsed) ? parsed[0] : undefined
  if (!isNpmPackResult(first)) {
    throw new Error(`Unexpected npm pack output for ${packageDir}: ${stdout}`)
  }
  return first
}

describe.each(publishablePackageDirs)('packaging: packages/%s', (packageDir) => {
  it('includes README.md in the published tarball', async () => {
    const pack = await runNpmPackDryRun(packageDir)
    const filePaths = pack.files.map((f) => f.path)
    expect(filePaths).toContain('README.md')
  })

  it('sets repository (with directory), homepage, and bugs in package.json', async () => {
    const pkg = await readPackageJson(packageDir)

    expect(pkg.homepage).toBe('https://github.com/mike-north/vaultkeeper#readme')
    expect(pkg.bugs).toBe('https://github.com/mike-north/vaultkeeper/issues')

    if (typeof pkg.repository !== 'object') {
      throw new Error(
        `Expected repository to be an object with a directory field for ${packageDir}`,
      )
    }
    expect(pkg.repository.type).toBe('git')
    expect(pkg.repository.url).toBe('git+https://github.com/mike-north/vaultkeeper.git')
    expect(pkg.repository.directory).toBe(`packages/${packageDir}`)
  })
})
