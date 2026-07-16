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
import { SetupError } from '../errors.js'

/** Name reported to the 1Password SDK for integration tracking. */
export const INTEGRATION_NAME = 'vaultkeeper'

/** npm package name of the optional 1Password SDK peer dependency. */
export const SDK_PACKAGE = '@1password/sdk'

/** Installation instructions surfaced when the SDK is missing. */
export const SDK_INSTALL_URL = 'https://developer.1password.com/docs/sdks/'

/**
 * Single source of truth for the "SDK not installed" error message, so the
 * backend, worker, and discovery modules report it identically.
 */
export const SDK_NOT_INSTALLED_MESSAGE = `1Password SDK (${SDK_PACKAGE}) is not installed. Install it to use the 1Password backend.`

/**
 * How long the per-access worker waits for `createClient()` to resolve during
 * a presence-covered `store`/`delete` write before treating the fresh action
 * as timed out (`PresenceTimeoutError`).
 *
 * @remarks
 * Shared between the worker (which starts the timer) and the backend (which
 * reports this value on the resulting {@link PresenceTimeoutError}), so the
 * two never drift. Reads are unaffected — issue #211 only extends presence
 * coverage to writes; see {@link https://github.com/mike-north/vaultkeeper/issues/211}.
 */
export const PRESENCE_WRITE_TIMEOUT_MS = 30_000

/**
 * Whether an error thrown by `import('@1password/sdk')` means the module could
 * not be resolved (i.e. the optional peer is not installed), as opposed to a
 * present-but-broken SDK (native binding failure, init throw, incompatible
 * Node). Only the former should be reported as "not installed" — the latter
 * must surface its real error so users don't reinstall something already there.
 *
 * @remarks
 * Node's loader rejects a missing import with `code` set directly on the error;
 * some loaders/wrappers instead attach the original via `error.cause`, so one
 * level of cause is inspected too.
 */
export function isModuleNotFoundError(error: unknown): boolean {
  const hasNotFoundCode = (value: unknown): boolean => {
    if (value === null || typeof value !== 'object' || !('code' in value)) {
      return false
    }
    const { code } = value
    return code === 'ERR_MODULE_NOT_FOUND' || code === 'MODULE_NOT_FOUND'
  }
  if (hasNotFoundCode(error)) {
    return true
  }
  if (error !== null && typeof error === 'object' && 'cause' in error) {
    return hasNotFoundCode(error.cause)
  }
  return false
}

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
  const candidates = [resolve(dir, '..', '..', 'package.json'), resolve(dir, '..', 'package.json')]
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
  throw new SetupError(
    `Could not read version from vaultkeeper package.json. Tried paths: ${candidates.join(', ')}`,
    'vaultkeeper package.json',
  )
}
