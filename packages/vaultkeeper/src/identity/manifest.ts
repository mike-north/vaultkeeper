/**
 * Trust manifest management — load, save, and query approved executable hashes.
 */

import * as fs from 'node:fs/promises'
import * as path from 'node:path'
import { FilesystemError } from '../errors.js'
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
 * Persist `manifest` to `configDir`, creating the directory if necessary.
 * @throws {@link FilesystemError} If the directory cannot be created or the
 *   manifest file cannot be written.
 * @internal
 */
export async function saveManifest(configDir: string, manifest: TrustManifest): Promise<void> {
  const manifestPath = path.join(configDir, MANIFEST_FILENAME)
  try {
    await fs.mkdir(configDir, { recursive: true })
    const entries: Record<string, TrustManifestEntry> = {}
    for (const [namespace, entry] of manifest) {
      entries[namespace] = entry
    }
    const raw: RawManifest = { version: 1, entries }
    await fs.writeFile(manifestPath, JSON.stringify(raw, null, 2), 'utf8')
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err)
    throw new FilesystemError(
      `Cannot write trust manifest at ${manifestPath}: ${detail}`,
      manifestPath,
      'write',
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
