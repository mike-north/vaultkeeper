/**
 * Packaging tests for every publishable package: asserts that `npm pack` would
 * include a README.md, that package.json carries repository/homepage/bugs
 * metadata, that every file path referenced by package.json (main/types/
 * module/exports/bin) actually exists in the packed tarball, and that exactly
 * one package (`@vaultkeeper/cli`) declares the `vaultkeeper` bin.
 * See https://github.com/mike-north/vaultkeeper/issues/63 and
 * https://github.com/mike-north/vaultkeeper/issues/64.
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

type ExportsValue = string | { [condition: string]: ExportsValue }

interface PackageJson {
  name: string
  homepage?: string
  bugs?: string
  repository?: RepositoryField | string
  main?: string
  module?: string
  types?: string
  bin?: string | Record<string, string>
  exports?: ExportsValue
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

function isExportsValue(value: unknown): value is ExportsValue {
  if (typeof value === 'string') {
    return true
  }
  return isPlainObject(value) && Object.values(value).every(isExportsValue)
}

function isStringRecord(value: unknown): value is Record<string, string> {
  return isPlainObject(value) && Object.values(value).every((v) => typeof v === 'string')
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
  if (value.main !== undefined && typeof value.main !== 'string') {
    return false
  }
  if (value.module !== undefined && typeof value.module !== 'string') {
    return false
  }
  if (value.types !== undefined && typeof value.types !== 'string') {
    return false
  }
  if (value.bin !== undefined && typeof value.bin !== 'string' && !isStringRecord(value.bin)) {
    return false
  }
  if (value.exports !== undefined && !isExportsValue(value.exports)) {
    return false
  }
  return true
}

/**
 * Collects every relative file path referenced by main/module/types/bin/exports,
 * so each one can be checked against the packed tarball's file list.
 */
function collectDeclaredPaths(pkg: PackageJson): string[] {
  const paths: string[] = []

  if (pkg.main !== undefined) paths.push(pkg.main)
  if (pkg.module !== undefined) paths.push(pkg.module)
  if (pkg.types !== undefined) paths.push(pkg.types)

  if (typeof pkg.bin === 'string') {
    paths.push(pkg.bin)
  } else if (pkg.bin !== undefined) {
    paths.push(...Object.values(pkg.bin))
  }

  function collectExportsLeaves(value: ExportsValue): void {
    if (typeof value === 'string') {
      paths.push(value)
      return
    }
    for (const nested of Object.values(value)) {
      collectExportsLeaves(nested)
    }
  }
  if (pkg.exports !== undefined) {
    collectExportsLeaves(pkg.exports)
  }

  return paths
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

  it('has every main/module/types/bin/exports path present in the packed tarball', async () => {
    const [pkg, pack] = await Promise.all([
      readPackageJson(packageDir),
      runNpmPackDryRun(packageDir),
    ])
    const filePaths = new Set(pack.files.map((f) => f.path))
    const declaredPaths = collectDeclaredPaths(pkg)

    // Regression guard for https://github.com/mike-north/vaultkeeper/issues/64:
    // package.json#types previously pointed at an API Extractor rollup file
    // that the release pipeline never generates, so it was absent from the
    // published tarball. This assertion fails against that pre-fix state.
    for (const declaredPath of declaredPaths) {
      const normalized = declaredPath.startsWith('./') ? declaredPath.slice(2) : declaredPath
      expect(
        filePaths,
        `${packageDir}: declared path "${declaredPath}" missing from tarball`,
      ).toContain(normalized)
    }
  })
})

/**
 * npm's `bin` field has two shapes: an object mapping command name -> script
 * (`{ "vaultkeeper": "./dist/bin.js" }`), or a string shorthand
 * (`"./dist/bin.js"`) which declares a single command named after the
 * package itself — the unscoped portion for scoped packages, e.g.
 * `@vaultkeeper/cli` -> `cli`. See
 * https://docs.npmjs.com/cli/v10/configuring-npm/package-json#bin.
 */
function declaredBinCommandNames(pkg: PackageJson): string[] {
  if (pkg.bin === undefined) {
    return []
  }
  if (typeof pkg.bin === 'string') {
    const slashIndex = pkg.name.lastIndexOf('/')
    return [slashIndex === -1 ? pkg.name : pkg.name.slice(slashIndex + 1)]
  }
  return Object.keys(pkg.bin)
}

describe('bin ownership', () => {
  it('declares the vaultkeeper bin in exactly one publishable package, @vaultkeeper/cli', async () => {
    const packages = await Promise.all(publishablePackageDirs.map((dir) => readPackageJson(dir)))

    const ownersOfVaultkeeperBin = packages
      .filter((pkg) => declaredBinCommandNames(pkg).includes('vaultkeeper'))
      .map((pkg) => pkg.name)

    expect(ownersOfVaultkeeperBin).toEqual(['@vaultkeeper/cli'])
  })

  it('declares no bin field on the vaultkeeper library package', async () => {
    const pkg = await readPackageJson('vaultkeeper')
    expect(pkg.bin).toBeUndefined()
  })
})
