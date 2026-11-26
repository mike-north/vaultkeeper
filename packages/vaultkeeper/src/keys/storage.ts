/**
 * Persistence for {@link KeyManager} state.
 *
 * @remarks
 * Key material is written under the vaultkeeper config directory, encrypted at
 * rest with AES-256-GCM via the shared {@link encryptGcm}/{@link decryptGcm}
 * helpers (the same authenticated cipher the {@link FileBackend} uses — no
 * bespoke crypto). Two owner-only (mode `0o600`) files are used:
 *
 * - `keys.enc` — the AES-256-GCM envelope of the JSON-serialized key state.
 * - `.keys.wrap` — the random 32-byte wrapping key that protects `keys.enc`.
 *
 * Persisting key material lets a JWE minted by one CLI process be authorized by
 * a later process within the token's validity window: the `kid` a token embeds
 * still resolves to a known key after the minting process exits. Without this,
 * every process generated fresh keys, so a cached token always failed
 * authorization with {@link KeyRevokedError}.
 *
 * @internal
 */

import * as fs from 'node:fs/promises'
import * as path from 'node:path'
import { encryptGcm, decryptGcm, getOrCreateWrapKey, readWrapKey } from '../util/at-rest.js'
import { hasErrorCode, publishFile } from '../util/publish-file.js'
import { DecryptionError, toFilesystemError } from '../errors.js'
import type { KeyMaterial, KeyStateSnapshot } from './types.js'

const KEY_STATE_FILE = 'keys.enc'
const KEY_WRAP_FILE = '.keys.wrap'

/** On-disk JSON shape for a single key (raw bytes base64-encoded). */
interface RawKeyMaterial {
  id: string
  key: string
  createdAt: string
}

/** On-disk JSON shape for the whole key state. */
interface RawKeyState {
  version: number
  current: RawKeyMaterial
  previous?: RawKeyMaterial
  gracePeriodExpiresAt?: number
}

function serializeKey(key: KeyMaterial): RawKeyMaterial {
  return {
    id: key.id,
    key: Buffer.from(key.key.buffer, key.key.byteOffset, key.key.byteLength).toString('base64'),
    createdAt: key.createdAt.toISOString(),
  }
}

/**
 * Type guard for a single {@link RawKeyMaterial}. Validates every field so a
 * corrupt or truncated file is treated as "no persisted state" rather than
 * yielding a malformed key.
 */
function isRawKeyMaterial(value: unknown): value is RawKeyMaterial {
  if (typeof value !== 'object' || value === null) return false
  if (!('id' in value) || typeof value.id !== 'string' || value.id === '') return false
  if (!('key' in value) || typeof value.key !== 'string' || value.key === '') return false
  if (!('createdAt' in value) || typeof value.createdAt !== 'string') return false
  return true
}

function deserializeKey(raw: RawKeyMaterial): KeyMaterial | undefined {
  const bytes = Buffer.from(raw.key, 'base64')
  const createdAt = new Date(raw.createdAt)
  if (bytes.byteLength !== 32 || Number.isNaN(createdAt.getTime())) {
    bytes.fill(0)
    return undefined
  }
  return { id: raw.id, key: bytes, createdAt }
}

/**
 * Type guard for {@link RawKeyState}.
 */
function isRawKeyState(value: unknown): value is RawKeyState {
  if (typeof value !== 'object' || value === null) return false
  if (!('version' in value) || typeof value.version !== 'number') return false
  if (!('current' in value) || !isRawKeyMaterial(value.current)) return false
  if ('previous' in value && value.previous !== undefined && !isRawKeyMaterial(value.previous)) {
    return false
  }
  if (
    'gracePeriodExpiresAt' in value &&
    value.gracePeriodExpiresAt !== undefined &&
    typeof value.gracePeriodExpiresAt !== 'number'
  ) {
    return false
  }
  return true
}

/**
 * Load persisted key state from `configDir`, or `undefined` when no valid state
 * exists yet (first run).
 * @internal
 */
export async function loadKeyState(configDir: string): Promise<KeyStateSnapshot | undefined> {
  const statePath = path.join(configDir, KEY_STATE_FILE)

  let envelope: string
  try {
    envelope = await fs.readFile(statePath, 'utf8')
  } catch (err) {
    if (hasErrorCode(err, 'ENOENT')) return undefined
    throw toFilesystemError(err, 'key state file', statePath, 'read')
  }

  const wrapKey = await readWrapKey(path.join(configDir, KEY_WRAP_FILE))
  try {
    envelope = decryptGcm(wrapKey, envelope, statePath)
  } finally {
    wrapKey.fill(0)
  }

  let parsed: unknown
  try {
    parsed = JSON.parse(envelope)
  } catch {
    throw new DecryptionError('Invalid key state JSON', statePath)
  }

  if (!isRawKeyState(parsed) || parsed.version !== 1) {
    throw new DecryptionError('Invalid key state', statePath)
  }

  const current = deserializeKey(parsed.current)
  if (current === undefined) throw new DecryptionError('Invalid current token key', statePath)

  const snapshot: KeyStateSnapshot = { current }

  if (
    parsed.previous !== undefined &&
    parsed.gracePeriodExpiresAt !== undefined &&
    Date.now() < parsed.gracePeriodExpiresAt
  ) {
    const previous = deserializeKey(parsed.previous)
    // Only surface the previous key while its grace period is still active; an
    // expired grace period is equivalent to no previous key at all.
    if (previous !== undefined) {
      snapshot.previous = previous
      snapshot.gracePeriodExpiresAt = parsed.gracePeriodExpiresAt
    }
  }

  return snapshot
}

/**
 * Persist `snapshot` to `configDir`, creating the directory if necessary. The
 * state file and its wrapping key are both written owner-only (`0o600`).
 *
 * Uses atomic write-then-rename so a concurrent {@link loadKeyState} never sees
 * a half-written envelope.
 * @internal
 */
export async function saveKeyState(configDir: string, snapshot: KeyStateSnapshot): Promise<void> {
  await persistKeyState(configDir, snapshot, true)
}

/** Publish initial token state and load the winner if another initializer got there first. */
export async function initializeKeyState(
  configDir: string,
  snapshot: KeyStateSnapshot,
): Promise<KeyStateSnapshot> {
  if (await persistKeyState(configDir, snapshot, false)) return snapshot
  const winner = await loadKeyState(configDir)
  if (winner === undefined) {
    throw new DecryptionError('Initial key state disappeared', path.join(configDir, KEY_STATE_FILE))
  }
  return winner
}

async function persistKeyState(
  configDir: string,
  snapshot: KeyStateSnapshot,
  replace: boolean,
): Promise<boolean> {
  // Creating the config directory can fail (e.g. its parent is read-only) on
  // the first `store`, which persists key state before any secret is written.
  // Surface a typed FilesystemError rather than leaking the raw Node
  // `EACCES: … mkdir '<path>'` text (issue #228).
  try {
    await fs.mkdir(configDir, { recursive: true, mode: 0o700 })
  } catch (err) {
    throw toFilesystemError(err, 'config directory', configDir, 'create')
  }

  const raw: RawKeyState = {
    version: 1,
    current: serializeKey(snapshot.current),
  }
  if (snapshot.previous !== undefined && snapshot.gracePeriodExpiresAt !== undefined) {
    raw.previous = serializeKey(snapshot.previous)
    raw.gracePeriodExpiresAt = snapshot.gracePeriodExpiresAt
  }

  const statePath = path.join(configDir, KEY_STATE_FILE)
  const wrapPath = path.join(configDir, KEY_WRAP_FILE)
  // An update must use the already-established key if the state exists.
  let stateExists = false
  if (replace) {
    try {
      await fs.stat(statePath)
      stateExists = true
    } catch (err) {
      if (!hasErrorCode(err, 'ENOENT')) {
        throw toFilesystemError(err, 'key state file', statePath, 'read')
      }
    }
  }
  const wrapKey = stateExists ? await readWrapKey(wrapPath) : await getOrCreateWrapKey(wrapPath)
  let envelope: string
  try {
    envelope = encryptGcm(wrapKey, JSON.stringify(raw))
  } finally {
    wrapKey.fill(0)
  }

  return publishFile(statePath, envelope, 'key state file', replace)
}
