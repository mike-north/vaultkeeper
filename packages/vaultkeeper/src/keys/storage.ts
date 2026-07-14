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
import { encryptGcm, decryptGcm, getOrCreateWrapKey } from '../util/at-rest.js'
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
    key: Buffer.from(key.key).toString('base64'),
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
  // A 32-byte AES-256 key is required; reject anything else as corrupt.
  if (bytes.byteLength !== 32) return undefined
  const createdAt = new Date(raw.createdAt)
  if (Number.isNaN(createdAt.getTime())) return undefined
  return { id: raw.id, key: new Uint8Array(bytes), createdAt }
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
 * exists yet (first run, or an unreadable/corrupt file).
 * @internal
 */
export async function loadKeyState(configDir: string): Promise<KeyStateSnapshot | undefined> {
  const statePath = path.join(configDir, KEY_STATE_FILE)

  let envelope: string
  try {
    envelope = await fs.readFile(statePath, 'utf8')
  } catch {
    return undefined
  }

  const wrapKey = await getOrCreateWrapKey(path.join(configDir, KEY_WRAP_FILE))
  let json: string
  try {
    json = decryptGcm(wrapKey, envelope)
  } catch {
    // Envelope failed authentication (tampered, or wrap key lost/rotated).
    // Treat as absent so a fresh key state is generated rather than crashing.
    return undefined
  } finally {
    wrapKey.fill(0)
  }

  let parsed: unknown
  try {
    parsed = JSON.parse(json)
  } catch {
    return undefined
  }

  if (!isRawKeyState(parsed)) return undefined

  const current = deserializeKey(parsed.current)
  if (current === undefined) return undefined

  const snapshot: KeyStateSnapshot = { current }

  if (parsed.previous !== undefined && parsed.gracePeriodExpiresAt !== undefined) {
    const previous = deserializeKey(parsed.previous)
    // Only surface the previous key while its grace period is still active; an
    // expired grace period is equivalent to no previous key at all.
    if (previous !== undefined && Date.now() < parsed.gracePeriodExpiresAt) {
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
  await fs.mkdir(configDir, { recursive: true, mode: 0o700 })

  const raw: RawKeyState = {
    version: 1,
    current: serializeKey(snapshot.current),
  }
  if (snapshot.previous !== undefined && snapshot.gracePeriodExpiresAt !== undefined) {
    raw.previous = serializeKey(snapshot.previous)
    raw.gracePeriodExpiresAt = snapshot.gracePeriodExpiresAt
  }

  const wrapKey = await getOrCreateWrapKey(path.join(configDir, KEY_WRAP_FILE))
  let envelope: string
  try {
    envelope = encryptGcm(wrapKey, JSON.stringify(raw))
  } finally {
    wrapKey.fill(0)
  }

  const statePath = path.join(configDir, KEY_STATE_FILE)
  const tmpPath = `${statePath}.${String(process.pid)}.tmp`
  await fs.writeFile(tmpPath, envelope, { encoding: 'utf8', mode: 0o600 })
  await fs.rename(tmpPath, statePath)
}
