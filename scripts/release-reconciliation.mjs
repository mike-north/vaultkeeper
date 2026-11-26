import { execFileSync } from 'node:child_process'
import { pathToFileURL } from 'node:url'

const wasmName = '@vaultkeeper/wasm'
const wasmManifest = 'packages/vaultkeeper-wasm/package.json'
const crateNames = ['vaultkeeper-core', 'vaultkeeper-cli']

function readManifest(commit, manifest, cwd) {
  return execFileSync('git', ['show', `${commit}:${manifest}`], { cwd, encoding: 'utf8' })
}

function workspaceVersion(manifest) {
  const section = manifest.split(/^\[/m).find((part) => part.startsWith('workspace.package]'))
  const version = /^version\s*=\s*"([^"]+)"\s*$/m.exec(section ?? '')?.[1]
  if (!version) {
    throw new TypeError('Missing version in Cargo.toml [workspace.package]')
  }
  return version
}

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

export async function missingCrates({ commit, publishedPackages, cwd, request = fetch }) {
  // Use the immutable push SHA. Changesets can switch branches while updating its PR.
  const previous = `${commit}^1`
  const version = workspaceVersion(readManifest(commit, 'Cargo.toml', cwd))
  if (version === workspaceVersion(readManifest(previous, 'Cargo.toml', cwd))) {
    return []
  }

  const wasmVersion = JSON.parse(readManifest(commit, wasmManifest, cwd)).version
  const previousWasmVersion = JSON.parse(readManifest(previous, wasmManifest, cwd)).version
  if (wasmVersion !== version || wasmVersion === previousWasmVersion) {
    return []
  }

  // The exact package in Changesets' publish result also covers npm replication lag.
  if (!publishedPackages.some((pkg) => pkg.name === wasmName && pkg.version === version)) {
    const url = `https://registry.npmjs.org/${encodeURIComponent(wasmName)}/${encodeURIComponent(version)}`
    const response = await registryResponse(url, request)
    if (response.status === 404) {
      return []
    }
    const metadata = await response.json()
    if (metadata.name !== wasmName || metadata.version !== version) {
      throw new TypeError(`Unexpected npm metadata for ${wasmName}@${version}`)
    }
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
  return results.filter((name) => name !== undefined)
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const { GITHUB_SHA: commit, PUBLISHED_PACKAGES: published } = process.env
  if (!commit || !/^[a-f0-9]{40}$/.test(commit)) {
    throw new TypeError('Expected a GitHub push SHA')
  }
  const missing = await missingCrates({ commit, publishedPackages: JSON.parse(published || '[]') })
  process.stdout.write(
    `core-missing=${missing.includes('vaultkeeper-core')}\ncli-missing=${missing.includes('vaultkeeper-cli')}\n`,
  )
}
