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

import { createHash, randomBytes, randomUUID } from 'node:crypto'
import * as fs from 'node:fs/promises'
import * as path from 'node:path'
import { setTimeout } from 'node:timers/promises'
import { encryptGcm, decryptGcm } from '../util/at-rest.js'
import { DecryptionError, FilesystemError, toFilesystemError } from '../errors.js'
import type { KeyMaterial, KeyStateSnapshot } from './types.js'

const KEY_STATE_FILE = 'keys.enc'
const KEY_WRAP_FILE = '.keys.wrap'

interface RawKeyMaterial {
  id: string
  key: string
  createdAt: string
}

interface RawKeyState {
  version: 1
  current: RawKeyMaterial
  previous?: RawKeyMaterial
  gracePeriodExpiresAt?: number
}

function hasCode(error: unknown, code: string): boolean {
  return error instanceof Error && 'code' in error && error.code === code
}

function recoveryError(statePath: string, reason: string): DecryptionError {
  return new DecryptionError(
    `Cannot load key state: ${reason}. Restore keys.enc and .keys.wrap from a matching backup before retrying.`,
    statePath,
  )
}

function isRawKeyMaterial(value: unknown): value is RawKeyMaterial {
  return (
    typeof value === 'object' &&
    value !== null &&
    'id' in value &&
    typeof value.id === 'string' &&
    value.id !== '' &&
    'key' in value &&
    typeof value.key === 'string' &&
    'createdAt' in value &&
    typeof value.createdAt === 'string'
  )
}

function isCounter(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0
}

function validRevocations(value: object): boolean {
  if ('revStateGen' in value && !isCounter(value.revStateGen)) return false
  if ('keyGenerations' in value) {
    const generations = value.keyGenerations
    if (
      typeof generations !== 'object' ||
      generations === null ||
      Array.isArray(generations) ||
      !Object.values(generations).every(isCounter)
    )
      return false
  }
  if ('jti' in value) {
    if (
      !Array.isArray(value.jti) ||
      !value.jti.every(
        (entry: unknown) =>
          typeof entry === 'object' &&
          entry !== null &&
          'jti' in entry &&
          typeof entry.jti === 'string' &&
          'exp' in entry &&
          isCounter(entry.exp),
      )
    )
      return false
  }
  return true
}

function isRawKeyState(value: unknown): value is RawKeyState {
  if (typeof value !== 'object' || value === null) return false
  if (!('version' in value) || value.version !== 1) return false
  if (!('current' in value) || !isRawKeyMaterial(value.current) || !validRevocations(value))
    return false
  if (!('previous' in value) && !('gracePeriodExpiresAt' in value)) return true
  return (
    'previous' in value &&
    isRawKeyMaterial(value.previous) &&
    value.previous.id !== value.current.id &&
    'gracePeriodExpiresAt' in value &&
    typeof value.gracePeriodExpiresAt === 'number' &&
    Number.isSafeInteger(value.gracePeriodExpiresAt) &&
    value.gracePeriodExpiresAt >= 0
  )
}

function validTimestamp(timestamp: string, date: Date): boolean {
  if (!Number.isFinite(date.getTime()) || date.getUTCFullYear() < 1970) return false
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/.test(timestamp)) return false
  return date.toISOString().slice(0, 19) === timestamp.slice(0, 19)
}

function deserializeKey(raw: RawKeyMaterial, statePath: string): KeyMaterial {
  const createdAt = new Date(raw.createdAt)
  const bytes = Buffer.from(raw.key, 'base64')
  if (
    bytes.length !== 32 ||
    bytes.toString('base64') !== raw.key ||
    !validTimestamp(raw.createdAt, createdAt)
  ) {
    bytes.fill(0)
    throw recoveryError(statePath, 'invalid key material')
  }
  return { id: raw.id, key: bytes, createdAt }
}

function serializeKey(key: KeyMaterial): RawKeyMaterial {
  const bytes = Buffer.from(key.key.buffer, key.key.byteOffset, key.key.byteLength)
  return { id: key.id, key: bytes.toString('base64'), createdAt: key.createdAt.toISOString() }
}

// lstat distinguishes a missing entry from a dangling symlink. Require a
// regular file before reading so an unexpected FIFO cannot block bootstrap.
async function readRegularFile(filePath: string, label: string): Promise<Buffer | undefined> {
  let stat
  try {
    stat = await fs.lstat(filePath)
  } catch (error) {
    if (hasCode(error, 'ENOENT')) return undefined
    throw toFilesystemError(error, label, filePath, 'read')
  }
  if (!stat.isFile()) {
    throw new DecryptionError(
      `Cannot read ${label}: expected a regular file. Check the path or restore it from backup.`,
      filePath,
    )
  }
  try {
    return await fs.readFile(filePath)
  } catch (error) {
    throw toFilesystemError(error, label, filePath, 'read')
  }
}

async function loadRaw(
  configDir: string,
): Promise<{ raw: RawKeyState; snapshot: KeyStateSnapshot; wrapDigest: string } | undefined> {
  const statePath = path.join(configDir, KEY_STATE_FILE)
  const envelope = await readRegularFile(statePath, 'key state file')
  if (envelope === undefined) return undefined

  const wrap = await readRegularFile(path.join(configDir, KEY_WRAP_FILE), 'wrapping key file')
  let parsed: unknown
  let wrapDigest: string
  try {
    if (wrap?.length !== 32) throw recoveryError(statePath, 'missing or invalid wrapping key')
    try {
      const encoded = envelope.toString('utf8')
      const parts = encoded.split(':')
      const [iv] = parts
      if (
        parts.length !== 3 ||
        iv?.length !== 16 ||
        !parts.every((part) => Buffer.from(part, 'base64').toString('base64') === part)
      ) {
        throw recoveryError(statePath, 'malformed encrypted envelope')
      }
      parsed = JSON.parse(decryptGcm(wrap, encoded, statePath))
      wrapDigest = createHash('sha256').update(wrap).digest('hex')
    } catch {
      throw recoveryError(
        statePath,
        'encrypted snapshot failed authentication or could not be parsed',
      )
    }
  } finally {
    wrap?.fill(0)
  }
  if (!isRawKeyState(parsed)) throw recoveryError(statePath, 'invalid snapshot format')

  const current = deserializeKey(parsed.current, statePath)
  const snapshot: KeyStateSnapshot = { current }
  if (parsed.previous !== undefined && parsed.gracePeriodExpiresAt !== undefined) {
    try {
      const previous = deserializeKey(parsed.previous, statePath)
      if (Date.now() < parsed.gracePeriodExpiresAt) {
        snapshot.previous = previous
        snapshot.gracePeriodExpiresAt = parsed.gracePeriodExpiresAt
      } else {
        previous.key.fill(0)
      }
    } catch (error) {
      current.key.fill(0)
      throw error
    }
  }
  return { raw: parsed, snapshot, wrapDigest }
}

/** Read existing state without writing either file. @internal */
export async function loadKeyState(configDir: string): Promise<KeyStateSnapshot | undefined> {
  return (await loadRaw(configDir))?.snapshot
}

async function publish(
  filePath: string,
  content: string | Buffer,
  replace: boolean,
): Promise<void> {
  const tmpPath = `${filePath}.${randomUUID()}.tmp`
  let ownsTemp = false
  try {
    const file = await fs.open(tmpPath, 'wx', 0o600)
    ownsTemp = true
    try {
      await file.writeFile(content)
    } finally {
      await file.close()
    }
    if (replace) await fs.rename(tmpPath, filePath)
    else await fs.link(tmpPath, filePath)
  } catch (error) {
    throw toFilesystemError(error, 'key storage file', filePath, 'write')
  } finally {
    if (ownsTemp) await fs.unlink(tmpPath).catch(() => undefined)
  }
}

async function writeSnapshot(
  configDir: string,
  snapshot: KeyStateSnapshot,
  prior: Awaited<ReturnType<typeof loadRaw>>,
): Promise<void> {
  const statePath = path.join(configDir, KEY_STATE_FILE)
  const wrapPath = path.join(configDir, KEY_WRAP_FILE)
  const existingWrap = await readRegularFile(wrapPath, 'wrapping key file')
  const wrap = existingWrap ?? randomBytes(32)
  try {
    if (wrap.length !== 32 || (prior !== undefined && existingWrap === undefined)) {
      throw recoveryError(statePath, 'missing or invalid wrapping key')
    }
    if (
      prior !== undefined &&
      prior.wrapDigest !== createHash('sha256').update(wrap).digest('hex')
    ) {
      throw recoveryError(statePath, 'wrapping key changed during the update')
    }
    if (existingWrap === undefined) {
      // A non-cooperating writer may have published state while the lock was
      // held. Do not create a wrapping key for that state.
      if ((await readRegularFile(statePath, 'key state file')) !== undefined) {
        throw recoveryError(statePath, 'key state appeared during initialization')
      }
      await publish(wrapPath, wrap, false)
    }

    // Keep native lease revocation metadata and any other unmodified fields.
    const raw: RawKeyState = { ...prior?.raw, version: 1, current: serializeKey(snapshot.current) }
    delete raw.previous
    delete raw.gracePeriodExpiresAt
    if (snapshot.previous !== undefined && snapshot.gracePeriodExpiresAt !== undefined) {
      raw.previous = serializeKey(snapshot.previous)
      raw.gracePeriodExpiresAt = snapshot.gracePeriodExpiresAt
    }
    await publish(statePath, encryptGcm(wrap, JSON.stringify(raw)), prior !== undefined)
  } finally {
    wrap.fill(0)
  }
}

/** Serialize persisted read-modify-write operations with native writers. @internal */
export async function updateKeyState(
  configDir: string,
  update: (current: KeyStateSnapshot | undefined) => KeyStateSnapshot,
): Promise<KeyStateSnapshot> {
  try {
    await fs.mkdir(configDir, { recursive: true, mode: 0o700 })
  } catch (error) {
    throw toFilesystemError(error, 'config directory', configDir, 'create')
  }

  const lockPath = path.join(configDir, 'keys.enc.lock')
  // Use the native writer's lock path and marker format. Publishing a complete
  // marker also avoids leaving an empty lock if writing the marker fails.
  for (let attempt = 0; ; attempt++) {
    try {
      await publish(lockPath, String(Date.now()), false)
      break
    } catch (error) {
      if (!hasCode(error, 'EEXIST')) throw error
      if (attempt === 49) {
        throw new FilesystemError(
          `Timed out waiting for the key state lock at ${lockPath}. Retry after other vault writers finish. If no writer is active, remove the abandoned lock file and retry.`,
          lockPath,
          'lock',
          error,
        )
      }
      await setTimeout(20)
    }
  }
  let loaded: KeyStateSnapshot | undefined
  let next: KeyStateSnapshot | undefined
  let succeeded = false
  try {
    const prior = await loadRaw(configDir)
    loaded = prior?.snapshot
    next = update(loaded)
    if (next !== loaded) await writeSnapshot(configDir, next, prior)
    succeeded = true
    return next
  } finally {
    if (loaded?.current !== next?.current || !succeeded) loaded?.current.key.fill(0)
    if (loaded?.previous !== next?.previous || !succeeded) loaded?.previous?.key.fill(0)
    if (!succeeded) {
      next?.current.key.fill(0)
      next?.previous?.key.fill(0)
    }
    await fs.unlink(lockPath).catch(() => undefined)
  }
}
