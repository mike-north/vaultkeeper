// A release is a synchronized Cargo and WASM version change across the original main push.
// Only an npm publication tied to that push's source permits publishing absent crate versions.
// A crates.io index 404 or an exact version missing from a valid index entry permits publishing.
import { execFileSync } from 'node:child_process'
import { pathToFileURL } from 'node:url'

// The WASM npm package carries the version shared by the two published Rust crates.
const wasmName = '@vaultkeeper/wasm'
const wasmManifest = 'packages/vaultkeeper-wasm/package.json'
const crateNames = ['vaultkeeper-core', 'vaultkeeper-cli']
const npmRegistry = 'https://registry.npmjs.org'
const releaseRepository = 'https://github.com/mike-north/vaultkeeper'
const releaseRef = 'refs/heads/main'
const provenanceType = 'https://slsa.dev/provenance/v1'
const commitSha = /^[a-f0-9]{40}$/

// Changesets may switch branches to update its version PR, so read manifests from Git objects.
function readManifest(commit, manifest, cwd) {
  return execFileSync('git', ['show', `${commit}:${manifest}`], { cwd, encoding: 'utf8' })
}

// The publishable crates inherit their version from Cargo's workspace package section.
function workspaceVersion(manifest) {
  const section = manifest.split(/^\[/m).find((part) => part.startsWith('workspace.package]'))
  const version = /^version\s*=\s*"([^"]+)"\s*$/m.exec(section ?? '')?.[1]
  if (!version) {
    throw new TypeError('Missing version in Cargo.toml [workspace.package]')
  }
  return version
}

function versionsAt(commit, cwd) {
  return {
    cargo: workspaceVersion(readManifest(commit, 'Cargo.toml', cwd)),
    wasm: JSON.parse(readManifest(commit, wasmManifest, cwd)).version,
  }
}

// Missing versions are a normal release state. Other registry failures must stop publication.
async function registryResponse(url, request) {
  const response = await request(url, {
    headers: { 'cache-control': 'no-cache' },
    signal: AbortSignal.timeout(30_000),
  })
  if (response.status !== 200 && response.status !== 404) {
    throw new TypeError(`Registry lookup failed for ${url}: HTTP ${response.status}`)
  }
  return response
}

// Trusted publishing can omit gitHead. npm verifies provenance at publish time and serves it
// from a version-specific endpoint. Match its tarball and release workflow before using its SHA.
async function provenanceSource(metadata, version, request) {
  const dist = metadata.dist
  if (dist?.attestations?.provenance?.predicateType !== provenanceType) return undefined

  const integrity = /^sha512-([A-Za-z0-9+/]{86}==)$/.exec(dist.integrity)?.[1]
  if (!integrity) return undefined
  const digest = Buffer.from(integrity, 'base64').toString('hex')

  const url = `${npmRegistry}/-/npm/v1/attestations/${encodeURIComponent(wasmName)}@${encodeURIComponent(version)}`
  const response = await registryResponse(url, request)
  if (response.status === 404) return undefined
  const { attestations } = await response.json()
  const payload = attestations?.find((entry) => entry.predicateType === provenanceType)?.bundle
    ?.dsseEnvelope?.payload
  if (typeof payload !== 'string') return undefined

  const statement = JSON.parse(Buffer.from(payload, 'base64').toString('utf8'))
  const subject = `pkg:npm/%40vaultkeeper/wasm@${version}`
  if (
    statement?._type !== 'https://in-toto.io/Statement/v1' ||
    statement.predicateType !== provenanceType ||
    !statement.subject?.some((entry) => entry.name === subject && entry.digest?.sha512 === digest)
  ) {
    return undefined
  }

  const build = statement.predicate?.buildDefinition
  const workflow = build?.externalParameters?.workflow
  if (
    build?.buildType !== 'https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1' ||
    workflow?.repository !== releaseRepository ||
    workflow.ref !== releaseRef ||
    workflow.path !== '.github/workflows/release.yml'
  ) {
    return undefined
  }
  return build.resolvedDependencies?.find(
    (entry) => entry.uri === `git+${releaseRepository}@${releaseRef}`,
  )?.digest?.gitCommit
}

// Main's first-parent history admits the release bump and any follow-ups in this push.
// A same-version commit from before the push, a later push, or a side branch cannot authorize recovery.
function validateSource(source, { before, commit, version, cwd }) {
  if (typeof source !== 'string' || !commitSha.test(source)) {
    throw new TypeError(`Missing or invalid npm source commit for ${wasmName}@${version}`)
  }
  if (source === commit) return

  const pushedCommits = execFileSync(
    'git',
    ['rev-list', '--first-parent', `${before}..${commit}`],
    {
      cwd,
      encoding: 'utf8',
    },
  )
    .trim()
    .split('\n')
  if (!pushedCommits.includes(source)) {
    throw new TypeError(`npm source commit for ${wasmName}@${version} is outside the release push`)
  }
  const sourceVersions = versionsAt(source, cwd)
  if (sourceVersions.cargo !== version || sourceVersions.wasm !== version) {
    throw new TypeError(
      `npm source commit for ${wasmName}@${version} has different release versions`,
    )
  }
}

// Return the crate names that still need publishing and the exact tree they must be built from.
export async function missingCrates({ before, commit, publishedPackages, cwd, request = fetch }) {
  if (
    typeof before !== 'string' ||
    !commitSha.test(before) ||
    typeof commit !== 'string' ||
    !commitSha.test(commit)
  ) {
    throw new TypeError('Expected the original GitHub push commit SHAs')
  }
  const noRelease = { missing: [], source: null }
  if (before === '0'.repeat(40)) return noRelease

  const { cargo: version, wasm } = versionsAt(commit, cwd)
  const previous = versionsAt(before, cwd)
  if (wasm !== version || previous.cargo === version || previous.wasm === version) {
    return noRelease
  }

  // A fresh Changesets publish used the checked-out push tip and may precede npm replication.
  let source = commit
  if (!publishedPackages.some((pkg) => pkg.name === wasmName && pkg.version === version)) {
    const url = `${npmRegistry}/${encodeURIComponent(wasmName)}/${encodeURIComponent(version)}`
    const response = await registryResponse(url, request)
    if (response.status === 404) {
      return noRelease
    }
    const metadata = await response.json()
    if (metadata.name !== wasmName || metadata.version !== version) {
      throw new TypeError(`Unexpected npm metadata for ${wasmName}@${version}`)
    }
    source = metadata.gitHead ?? (await provenanceSource(metadata, version, request))
    validateSource(source, { before, commit, version, cwd })
  }

  const results = await Promise.all(
    crateNames.map(async (name) => {
      const response = await registryResponse(`https://index.crates.io/va/ul/${name}`, request)
      if (response.status === 404) {
        return name
      }
      // Yanked versions still occupy their version number and cannot be republished.
      const entries = (await response.text()).trim().split('\n').map(JSON.parse)
      if (entries.some((entry) => entry.name !== name || typeof entry.vers !== 'string')) {
        throw new TypeError(`Unexpected crates.io index metadata for ${name}`)
      }
      return entries.some((entry) => entry.vers === version) ? undefined : name
    }),
  )
  return { missing: results.filter((name) => name !== undefined), source }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const { PUSH_BEFORE: before, GITHUB_SHA: commit, PUBLISHED_PACKAGES: published } = process.env
  const { missing, source } = await missingCrates({
    before,
    commit,
    publishedPackages: JSON.parse(published || '[]'),
  })
  process.stdout.write(
    `source=${source ?? ''}\ncore-missing=${missing.includes('vaultkeeper-core')}\ncli-missing=${missing.includes('vaultkeeper-cli')}\n`,
  )
}
