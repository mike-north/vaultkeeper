/**
 * Shared constants for 1Password SDK integration.
 *
 * @remarks
 * Centralised here so the backend, worker, and discovery modules stay in sync.
 *
 * @internal
 */

import { readFileSync, existsSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

/** Name reported to the 1Password SDK for integration tracking. */
export const INTEGRATION_NAME = 'vaultkeeper'

let cachedVersion: string | undefined

/**
 * Version reported to the 1Password SDK.
 *
 * @remarks
 * Lazily derived from packages/vaultkeeper/package.json on first call so that
 * consumers who never use the 1Password backend pay no I/O cost at import time.
 * The result is memoized for subsequent calls.
 *
 * @internal
 */
export function getIntegrationVersion(): string {
  if (cachedVersion !== undefined) return cachedVersion

  const dir = dirname(fileURLToPath(import.meta.url))
  // Source: src/backend/ → ../../package.json
  // Bundled: dist/ → ../package.json
  const candidates = [
    resolve(dir, '..', '..', 'package.json'),
    resolve(dir, '..', 'package.json'),
  ]
  for (const candidate of candidates) {
    if (!existsSync(candidate)) continue
    const raw: unknown = JSON.parse(readFileSync(candidate, 'utf8'))
    if (
      raw !== null &&
      typeof raw === 'object' &&
      'version' in raw &&
      typeof raw.version === 'string'
    ) {
      cachedVersion = raw.version
      return cachedVersion
    }
  }
  throw new Error(
    `Could not read version from vaultkeeper package.json. Tried paths: ${candidates.join(', ')}`,
  )
}
