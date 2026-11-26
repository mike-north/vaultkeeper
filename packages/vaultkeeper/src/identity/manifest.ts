/**
 * Trust manifest management — load, save, and query approved executable hashes.
 */

import { randomUUID } from 'node:crypto'
import * as fs from 'node:fs/promises'
import * as path from 'node:path'
import { lockTrustManifest } from '../../../vaultkeeper-wasm/host/trust-lock.js'
import { FilesystemError, toFilesystemError } from '../errors.js'
import type { TrustManifest, TrustManifestEntry } from './types.js'

const MANIFEST_FILENAME = 'trust-manifest.json'

/** Raw shape persisted to disk (plain object, not a Map). */
interface RawManifest {
  version: number
  entries: Record<string, TrustManifestEntry>
}

/**
 * Type guard that checks `value` is an object with a `version: number` and
 * `entries` object property, matching {@link RawManifest}.
 *
 * We avoid type assertions by narrowing through the `in` operator and
 * `typeof` checks. The discriminated union `unknown → object` chain lets
 * TypeScript track narrowness without any `as` casts.
 */
function isRawManifest(value: unknown): value is RawManifest {
  if (typeof value !== 'object' || value === null) return false
  if (!('version' in value) || typeof value.version !== 'number') return false
  if (!('entries' in value) || typeof value.entries !== 'object' || value.entries === null)
    return false
  return true
}

/**
 * Type guard for a single {@link TrustManifestEntry}.
 */
function isTrustManifestEntry(value: unknown): value is TrustManifestEntry {
  if (typeof value !== 'object' || value === null) return false
  if (!('hashes' in value) || !Array.isArray(value.hashes)) return false
  if (!('trustTier' in value)) return false
  const { trustTier } = value
  if (trustTier !== 1 && trustTier !== 2 && trustTier !== 3) return false
  return true
}

/**
 * Load the trust manifest from `configDir`.
 * Returns an empty `Map` if the manifest file does not yet exist.
 * @throws {@link FilesystemError} If the file exists but cannot be read, or its
 *   contents are not valid JSON.
 * @internal
 */
export async function loadManifest(configDir: string): Promise<TrustManifest> {
  const manifestPath = path.join(configDir, MANIFEST_FILENAME)
  let rawText: string
  try {
    rawText = await fs.readFile(manifestPath, 'utf8')
  } catch (err) {
    if (typeof err === 'object' && err !== null && 'code' in err && err.code === 'ENOENT') {
      return new Map()
    }
    const detail = err instanceof Error ? err.message : String(err)
    throw new FilesystemError(
      `Cannot read trust manifest at ${manifestPath}: ${detail}`,
      manifestPath,
      'read',
      err,
    )
  }

  let parsed: unknown
  try {
    parsed = JSON.parse(rawText)
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err)
    throw new FilesystemError(
      `Trust manifest at ${manifestPath} is not valid JSON: ${detail}`,
      manifestPath,
      'read',
      err,
    )
  }

  if (!isRawManifest(parsed)) {
    return new Map()
  }

  const manifest: TrustManifest = new Map()
  for (const [namespace, entry] of Object.entries(parsed.entries)) {
    if (isTrustManifestEntry(entry)) {
      manifest.set(namespace, { hashes: [...entry.hashes], trustTier: entry.trustTier })
    }
  }
  return manifest
}

/**
 * Read, conditionally update, and publish a manifest under one process-shared lock.
 * Returning undefined leaves the manifest unchanged.
 * @internal
 */
export async function updateManifest(
  configDir: string,
  update: (current: TrustManifest) => TrustManifest | undefined,
): Promise<TrustManifest> {
  return withManifestLock(configDir, async (dir) => {
    const current = await loadManifest(dir)
    const updated = update(current)
    if (updated === undefined) return current
    await publishManifest(dir, updated)
    return updated
  })
}

async function withManifestLock<T>(
  configDir: string,
  operation: (dir: string) => Promise<T>,
): Promise<T> {
  const dir = path.resolve(configDir)
  try {
    await fs.mkdir(dir, { recursive: true })
  } catch (err) {
    throw toFilesystemError(err, 'trust-manifest directory', configDir, 'create')
  }
  const lockPath = path.join(dir, MANIFEST_FILENAME + '.lock')
  let release: () => void
  try {
    release = await lockTrustManifest(lockPath)
  } catch (err) {
    throw toFilesystemError(err, 'trust manifest', lockPath, 'lock')
  }

  try {
    return await operation(dir)
  } finally {
    release()
  }
}

/**
 * Persist `manifest` to `configDir`, creating the directory if necessary.
 * @throws {@link FilesystemError} If the directory cannot be created or the
 *   manifest file cannot be written.
 * @internal
 */
export async function saveManifest(configDir: string, manifest: TrustManifest): Promise<void> {
  await withManifestLock(configDir, (dir) => publishManifest(dir, manifest))
}

async function publishManifest(configDir: string, manifest: TrustManifest): Promise<void> {
  const manifestPath = path.join(configDir, MANIFEST_FILENAME)
  const raw: RawManifest = { version: 1, entries: Object.fromEntries(manifest) }
  const temporaryPath = manifestPath + '.' + randomUUID() + '.tmp'
  let written = false
  try {
    await fs.writeFile(temporaryPath, JSON.stringify(raw, null, 2), {
      flag: 'wx',
      encoding: 'utf8',
      mode: 0o600,
    })
    written = true
    await fs.rename(temporaryPath, manifestPath)
  } catch (err) {
    if (
      written ||
      !(typeof err === 'object' && err !== null && 'code' in err && err.code === 'EEXIST')
    ) {
      await fs.unlink(temporaryPath).catch(() => undefined)
    }
    const detail = err instanceof Error ? err.message : String(err)
    throw new FilesystemError(
      `Cannot write trust manifest at ${manifestPath}: ${detail}`,
      manifestPath,
      'write',
      err,
    )
  }
}

/**
 * Return a new manifest that includes `hash` under `namespace`.
 * If the namespace does not yet exist it is created with tier 3 (Unverified).
 * The trust tier of an existing entry is not changed.
 * @internal
 */
export function addTrustedHash(
  manifest: TrustManifest,
  namespace: string,
  hash: string,
): TrustManifest {
  const next = new Map(manifest)
  const existing = next.get(namespace)
  if (existing === undefined) {
    next.set(namespace, { hashes: [hash], trustTier: 3 })
  } else if (!existing.hashes.includes(hash)) {
    next.set(namespace, { hashes: [...existing.hashes, hash], trustTier: existing.trustTier })
  }
  return next
}

/**
 * Return `true` if `hash` is in the approved list for `namespace`.
 * @internal
 */
export function isTrusted(manifest: TrustManifest, namespace: string, hash: string): boolean {
  const entry = manifest.get(namespace)
  if (entry === undefined) return false
  return entry.hashes.includes(hash)
}
