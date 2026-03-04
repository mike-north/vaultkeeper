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

/**
 * Version reported to the 1Password SDK.
 * Derived from packages/vaultkeeper/package.json at runtime so it stays in
 * sync automatically after changesets version bumps.
 */
function readPackageVersion(): string {
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
      return raw.version
    }
  }
  throw new Error('Could not read version from vaultkeeper package.json')
}

export const INTEGRATION_VERSION: string = readPackageVersion()
