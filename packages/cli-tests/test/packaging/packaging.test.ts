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
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import * as os from 'node:os'
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
  peerDependencies?: Record<string, string>
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
  if (value.peerDependencies !== undefined && !isStringRecord(value.peerDependencies)) {
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

interface NpmPackJsonEntry {
  filename: string
}

function isNpmPackJsonEntry(value: unknown): value is NpmPackJsonEntry {
  return isPlainObject(value) && typeof value.filename === 'string'
}

/**
 * Packs the given package for real (not `--dry-run`) into a throwaway temp
 * directory, then extracts README.md from the resulting tarball and returns
 * its text content. `--dry-run` only reports the file list, so it cannot
 * prove that a guaranteed section survived intact — only that a file named
 * README.md is present.
 */
async function readPackedReadme(packageDir: string): Promise<string> {
  const cwd = path.join(repoRoot, 'packages', packageDir)
  const tmpDir = await mkdtemp(path.join(os.tmpdir(), 'vaultkeeper-pack-'))
  try {
    const { stdout } = await execFileAsync(
      'npm',
      ['pack', '--json', '--pack-destination', tmpDir],
      { cwd },
    )
    const parsed: unknown = JSON.parse(stdout)
    const first: unknown = Array.isArray(parsed) ? parsed[0] : undefined
    if (!isNpmPackJsonEntry(first)) {
      throw new Error(`Unexpected npm pack output for ${packageDir}: ${stdout}`)
    }
    const tarballPath = path.join(tmpDir, first.filename)
    const { stdout: readmeContent } = await execFileAsync('tar', [
      '-xOf',
      tarballPath,
      'package/README.md',
    ])
    return readmeContent
  } finally {
    await rm(tmpDir, { recursive: true, force: true })
  }
}

describe.each(publishablePackageDirs)('packaging: packages/%s', (packageDir) => {
  it('includes README.md in the published tarball', async () => {
    const pack = await runNpmPackDryRun(packageDir)
    const filePaths = pack.files.map((f) => f.path)
    expect(filePaths).toContain('README.md')
  })

  it('includes LICENSE in the published tarball', async () => {
    // Regression guard for https://github.com/mike-north/vaultkeeper/issues/184:
    // each publishable package must carry its own LICENSE. A root-only LICENSE
    // is not packed — npm pack only considers files under the package's own
    // directory — so without a per-package LICENSE the published tarball would
    // ship no license text. This fails against the pre-fix state (root LICENSE
    // only, no per-package copy).
    const pack = await runNpmPackDryRun(packageDir)
    const filePaths = pack.files.map((f) => f.path)
    expect(filePaths).toContain('LICENSE')
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
 * Regression guard for https://github.com/mike-north/vaultkeeper/issues/179:
 * the tarball-inclusion test above only proves README.md exists in the
 * packed `vaultkeeper` tarball, not that its guaranteed content survived — a
 * future edit could silently strip a section (e.g. the error hierarchy or
 * the full `VaultConfig` reference) while every existing packaging assertion
 * kept passing. Each sentinel anchors a section that must ship intact.
 */
describe('packaging: packages/vaultkeeper README content', () => {
  it('retains guaranteed sections in the packed tarball', async () => {
    const readme = await readPackedReadme('vaultkeeper')

    const sentinels = [
      'Multiple secrets in one request', // dedicated section heading
      'InvalidKeyMaterialError', // error hierarchy entry
      'gracePeriodDays', // full VaultConfig field reference
      'Doctor / preflight checks', // doctor section heading
    ]

    for (const sentinel of sentinels) {
      expect(readme, `packed vaultkeeper README missing "${sentinel}"`).toContain(sentinel)
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

/**
 * Regression guard for https://github.com/mike-north/vaultkeeper/issues/156:
 * `test-helpers`' `vaultkeeper` peerDependency previously used `workspace:^`,
 * which publishes as a caret range (e.g. `^0.6.0`) that a routine 0.x
 * `vaultkeeper` minor bump exits — and changesets forces a major bump on any
 * peer-dependent whenever the dependency's release is non-patch, regardless
 * of whether the published range actually still allows the new version. An
 * explicit range with an upper bound below `1.0.0` keeps routine 0.x minors
 * in range (so the cascade only fires deliberately, once `vaultkeeper`
 * reaches 1.0.0). This assertion fails against the pre-fix `workspace:^`
 * declaration.
 */
describe('peer dependency stability', () => {
  it('test-helpers declares an explicit vaultkeeper peer range with an upper bound below 1.0.0', async () => {
    const pkg = await readPackageJson('test-helpers')
    const range = pkg.peerDependencies?.vaultkeeper

    expect(range).toBeDefined()
    expect(range).not.toMatch(/^workspace:/)
    expect(range).toMatch(/<\s*1(\.0\.0)?(\s|$)/)
  })
})
