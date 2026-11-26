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

import { randomUUID } from 'node:crypto'
import { setTimeout } from 'node:timers/promises'
import * as fs from 'node:fs/promises'
import * as path from 'node:path'
import { encryptGcm, decryptGcm, getOrCreateWrapKey } from '../util/at-rest.js'
import { DecryptionError, FilesystemError, VaultError, toFilesystemError } from '../errors.js'
import { KeyManager } from './manager.js'
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
  try {
    const createdAt = new Date(raw.createdAt)
    if (bytes.byteLength !== 32 || Number.isNaN(createdAt.getTime())) return undefined
    return { id: raw.id, key: new Uint8Array(bytes), createdAt }
  } finally {
    bytes.fill(0)
  }
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
  try {
    return (await readKeyState(configDir))?.snapshot
  } catch (err) {
    if (err instanceof DecryptionError) return undefined
    throw err
  }
}

function isMissing(err: unknown): boolean {
  return err instanceof Error && 'code' in err && err.code === 'ENOENT'
}

async function readKeyState(
  configDir: string,
): Promise<{ snapshot: KeyStateSnapshot; json: string } | undefined> {
  const statePath = path.join(configDir, KEY_STATE_FILE)
  let envelope: string
  try {
    envelope = await fs.readFile(statePath, 'utf8')
  } catch (err) {
    if (isMissing(err)) return undefined
    throw toFilesystemError(err, 'key state file', statePath, 'read')
  }

  const wrapPath = path.join(configDir, KEY_WRAP_FILE)
  let wrapKey: Buffer
  try {
    wrapKey = await fs.readFile(wrapPath)
  } catch (err) {
    if (isMissing(err)) throw new DecryptionError('Wrapping key is missing', wrapPath)
    throw toFilesystemError(err, 'wrapping key file', wrapPath, 'read')
  }
  let json: string
  try {
    json = decryptGcm(wrapKey, envelope, statePath)
  } finally {
    wrapKey.fill(0)
  }

  const corrupt = new DecryptionError('Invalid key state', statePath)
  let parsed: unknown
  try {
    parsed = JSON.parse(json)
  } catch {
    throw corrupt
  }
  if (!isRawKeyState(parsed) || parsed.version !== 1) throw corrupt
  return { snapshot: snapshotFromRaw(parsed, corrupt), json }
}

function snapshotFromRaw(parsed: RawKeyState, corrupt: DecryptionError): KeyStateSnapshot {
  const current = deserializeKey(parsed.current)
  if (current === undefined) throw corrupt

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

// The input has already passed JSON.parse. Scanning member boundaries lets
// us retain the original JSON for lease metadata, including u64 values that
// JavaScript numbers cannot represent exactly.
function retainMetadata(json: string): string[] {
  const retained: string[] = []
  const first = json.indexOf('{') + 1
  let start = first
  let depth = 0
  const keyFields = new Set(['version', 'current', 'previous', 'gracePeriodExpiresAt'])
  for (const token of json.slice(first).matchAll(/"(?:[^"\\]|\\[\s\S])*"|[{}[\],]/g)) {
    const index = first + token.index
    if (depth === 0 && (token[0] === ',' || token[0] === '}')) {
      const member = json.slice(start, index).trim()
      const name = /^("(?:[^"\\]|\\[\s\S])*")\s*:/.exec(member)?.[1]
      if (name !== undefined) {
        const decoded: unknown = JSON.parse(name)
        if (typeof decoded === 'string' && !keyFields.has(decoded)) retained.push(member)
      }
      start = index + 1
    } else if (token[0] === '{' || token[0] === '[') {
      depth++
    } else if (token[0] === '}' || token[0] === ']') {
      depth--
    }
  }
  return retained
}

async function withKeyStateLock<T>(configDir: string, operation: () => Promise<T>): Promise<T> {
  // Creating the config directory can fail (e.g. its parent is read-only) on
  // the first `store`, which persists key state before any secret is written.
  // Surface a typed FilesystemError rather than leaking the raw Node
  // `EACCES: … mkdir '<path>'` text (issue #228).
  try {
    await fs.mkdir(configDir, { recursive: true, mode: 0o700 })
  } catch (err) {
    throw toFilesystemError(err, 'config directory', configDir, 'create')
  }

  const lockPath = path.join(configDir, 'keys.enc.lock')
  for (let attempt = 0; ; attempt++) {
    try {
      const lock = await fs.open(lockPath, 'wx', 0o600)
      try {
        await lock.close()
      } catch (err) {
        await fs.unlink(lockPath).catch(() => undefined)
        throw err
      }
      break
    } catch (err) {
      if (!(err instanceof Error && 'code' in err && err.code === 'EEXIST')) {
        throw toFilesystemError(err, 'key-state lock', lockPath, 'create')
      }
      if (attempt === 49) {
        throw new FilesystemError(
          'Timed out waiting for the key-state lock. If abandoned, remove it only after stopping all key-state writers.',
          lockPath,
          'lock',
          err,
        )
      }
      await setTimeout(2)
    }
  }

  try {
    return await operation()
  } finally {
    await fs.unlink(lockPath).catch(() => undefined)
  }
}

/** Create an encrypted key store from a snapshot. @internal */
export async function saveKeyState(configDir: string, snapshot: KeyStateSnapshot): Promise<void> {
  await withKeyStateLock(configDir, async () => {
    const statePath = path.join(configDir, KEY_STATE_FILE)
    try {
      await fs.stat(statePath)
    } catch (err) {
      if (!isMissing(err)) throw toFilesystemError(err, 'key state file', statePath, 'read')
      await writeKeyState(configDir, snapshot)
      return
    }
    throw new VaultError('Key state already exists; use vault rotation or revocation to update it')
  })
}

/** Load or initialize the key manager, rechecking under the writer lock. @internal */
export async function initializeKeyManager(configDir: string): Promise<KeyManager> {
  const manager = new KeyManager()
  const loaded = await readKeyState(configDir)
  if (loaded !== undefined) {
    manager.hydrate(loaded.snapshot)
    return manager
  }
  return withKeyStateLock(configDir, async () => {
    const existing = await readKeyState(configDir)
    if (existing !== undefined) {
      manager.hydrate(existing.snapshot)
    } else {
      await manager.init()
      const snapshot = manager.snapshot()
      try {
        await writeKeyState(configDir, snapshot)
      } catch (err) {
        snapshot.current.key.fill(0)
        throw err
      }
    }
    return manager
  })
}

/** Update authoritative key state under the shared writer lock. @internal */
export async function mutateKeyManager(
  configDir: string,
  liveManager: KeyManager,
  mutate: (manager: KeyManager) => void,
): Promise<void> {
  await withKeyStateLock(configDir, async () => {
    const loaded = await readKeyState(configDir)
    if (loaded === undefined) {
      throw new DecryptionError('Key state is missing', path.join(configDir, KEY_STATE_FILE))
    }
    const manager = new KeyManager(false)
    manager.hydrate(loaded.snapshot)
    let updated: KeyStateSnapshot | undefined
    let published = false
    try {
      mutate(manager)
      updated = manager.snapshot()
      await writeKeyState(configDir, updated, retainMetadata(loaded.json))
      liveManager.hydrate(updated)
      published = true
    } finally {
      const kept = published ? [updated?.current, updated?.previous] : []
      for (const key of [
        loaded.snapshot.current,
        loaded.snapshot.previous,
        updated?.current,
        updated?.previous,
      ]) {
        if (key !== undefined && !kept.includes(key)) key.key.fill(0)
      }
    }
  })
}

async function writeKeyState(
  configDir: string,
  snapshot: KeyStateSnapshot,
  metadata: string[] = [],
): Promise<void> {
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
    const keys = JSON.stringify(raw)
    const json = metadata.length === 0 ? keys : `${keys.slice(0, -1)},${metadata.join(',')}}`
    envelope = encryptGcm(wrapKey, json)
  } finally {
    wrapKey.fill(0)
  }

  const statePath = path.join(configDir, KEY_STATE_FILE)
  const tmpPath = `${statePath}.${randomUUID()}.tmp`
  // Keep the write and the rename in separate try/catch blocks so the reported
  // FilesystemError path matches whichever step actually failed: the temp file
  // on a write failure (e.g. EACCES/ENOSPC creating it), the final state file
  // on a rename failure. A single shared catch would always blame `statePath`.
  try {
    await fs.writeFile(tmpPath, envelope, { encoding: 'utf8', mode: 0o600 })
  } catch (err) {
    await fs.unlink(tmpPath).catch(() => undefined)
    throw toFilesystemError(err, 'key state file', tmpPath, 'write')
  }
  try {
    await fs.rename(tmpPath, statePath)
  } catch (err) {
    await fs.unlink(tmpPath).catch(() => undefined)
    throw toFilesystemError(err, 'key state file', statePath, 'write')
  }
}
