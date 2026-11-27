/**
 * YubiKey backend implementation.
 *
 * @remarks
 * Stores secrets protected by a YubiKey using the `ykman` CLI tool.
 * Secrets are encrypted using AES-256-GCM with a key derived from the
 * YubiKey's HMAC-SHA1 challenge-response (slot 2) via HKDF-SHA-256.
 *
 * Encrypted file format (version 1, all parts base64-encoded, colon-separated):
 *   1:<iv>:<authTag>:<ciphertext>
 *
 * Version 2 adds a Base64 UTF-16LE ID as the fifth field for IDs whose UTF-8
 * path can have more than one spelling. The field is authenticated as GCM AAD.
 * Legacy OpenSSL CBC files have no version prefix.
 */

import * as fs from 'node:fs/promises'
import type { Dirent } from 'node:fs'
import * as path from 'node:path'
import * as os from 'node:os'
import * as crypto from 'node:crypto'
import { execCommandFull } from '../util/exec.js'
import {
  SecretNotFoundError,
  PluginNotFoundError,
  DeviceNotPresentError,
  DecryptionError,
  FilesystemError,
  SetupError,
  ExecError,
  toFilesystemError,
} from '../errors.js'
import type { ListableBackend, PresenceCapableBackend, BackendCapabilities } from './types.js'

const YKMAN_INSTALL_URL = 'https://developers.yubico.com/yubikey-manager/'
const STORAGE_DIR_NAME = path.join('.vaultkeeper', 'yubikey')
const DEVICE_TIMEOUT_MS = 5000

/** AES-256-GCM constants */
const GCM_IV_BYTES = 12
const GCM_KEY_BYTES = 32
const GCM_TAG_LENGTH_BITS = 128

/** Ordinary and spelling-bearing GCM records retain the same canonical entry path. */
const FORMAT_VERSION = '1'
const IDENTITY_FORMAT_VERSION = '2'

/** OpenSSL's legacy salted envelope still identifies a record for inventory and cleanup. */
const LEGACY_OPENSSL_MAGIC = Buffer.from('Salted__')

/**
 * Resolve the storage directory for a YubikeyBackend instance.
 *
 * When `configuredPath` is provided (from `BackendConfig.path`), encrypted
 * secrets are stored directly under that directory. Otherwise the default
 * `$HOME/.vaultkeeper/yubikey` location is used.
 */
function resolveStorageDir(configuredPath?: string): string {
  // Config validation (see validateConfig) rejects empty/whitespace-only
  // paths, so any defined value here is guaranteed non-blank.
  if (configuredPath !== undefined) {
    return configuredPath
  }
  return path.join(os.homedir(), STORAGE_DIR_NAME)
}

/** Path shared by v1 records and older clients that normalized every ID to UTF-8. */
function getLegacyEntryPath(storageDir: string, id: string): string {
  const safeId = Buffer.from(id, 'utf8').toString('hex')
  return path.join(storageDir, `${safeId}.enc`)
}

/** A replacement code point can have more than one original JavaScript spelling. */
function exactIdentity(id: string): Buffer | undefined {
  return Buffer.from(id, 'utf8').toString('utf8').includes('\ufffd')
    ? Buffer.from(id, 'utf16le')
    : undefined
}

/** Hash the exact UTF-16 code units so ambiguous spellings occupy disjoint, bounded filenames. */
function getEntryPath(storageDir: string, id: string): string {
  const identity = exactIdentity(id)
  return identity === undefined
    ? getLegacyEntryPath(storageDir, id)
    : path.join(storageDir, `id-${crypto.createHash('sha256').update(identity).digest('hex')}.enc`)
}

/** Decode the byte-preserving ID field without letting permissive Base64 rewrite its value. */
function decodeIdentity(encoded: string): Buffer | undefined {
  const identity = Buffer.from(encoded, 'base64')
  return identity.length > 0 && identity.length % 2 === 0 && identity.toString('base64') === encoded
    ? identity
    : undefined
}

/**
 * Identify YubiKey envelopes even when another backend uses the same filenames.
 * Null identifies a legacy record whose spelling may need its original index.
 */
function inventoryRecordId(entry: Buffer): string | null | undefined {
  if (entry.subarray(0, LEGACY_OPENSSL_MAGIC.length).equals(LEGACY_OPENSSL_MAGIC)) {
    return null
  }
  const separator = 0x3a
  const versionEnd = entry.indexOf(separator)
  if (
    versionEnd <= 0 ||
    !entry.subarray(0, versionEnd).every((byte) => byte >= 0x30 && byte <= 0x39)
  ) {
    return undefined
  }
  const ivEnd = entry.indexOf(separator, versionEnd + 1)
  const tagEnd = ivEnd === -1 ? -1 : entry.indexOf(separator, ivEnd + 1)
  if (tagEnd === -1) {
    return undefined // A FileBackend envelope has only three fields.
  }
  const version = entry.subarray(0, versionEnd).toString('latin1')
  const ciphertextEnd = entry.indexOf(separator, tagEnd + 1)
  if (version !== IDENTITY_FORMAT_VERSION) {
    return ciphertextEnd === -1 ? null : undefined
  }
  if (ciphertextEnd === -1 || entry.indexOf(separator, ciphertextEnd + 1) !== -1) {
    return undefined
  }
  const identity = decodeIdentity(entry.subarray(ciphertextEnd + 1).toString('latin1'))
  return identity?.toString('utf16le')
}

/** Resolve uniquely indexed spellings for legacy filenames that have multiple possible IDs. */
async function legacyInventoryAliases(
  storageDir: string,
  ids: ReadonlySet<string>,
): Promise<ReadonlyMap<string, string | null>> {
  const aliases = new Map<string, string | null>()
  if (ids.size === 0) {
    return aliases
  }

  let metadata: unknown
  try {
    metadata = JSON.parse(await fs.readFile(path.join(storageDir, 'metadata.json'), 'utf8'))
  } catch {
    // The record survives without its index, but its spelling may be unrecoverable.
    return aliases
  }
  if (typeof metadata !== 'object' || metadata === null || !('entries' in metadata)) {
    return aliases
  }
  const { entries } = metadata
  if (
    typeof entries !== 'object' ||
    entries === null ||
    Array.isArray(entries) ||
    !Object.values(entries).every((entry) => typeof entry === 'string')
  ) {
    return aliases
  }
  for (const [id, indexedPath] of Object.entries(entries)) {
    const canonical = Buffer.from(id, 'utf8').toString('utf8')
    // A moved store can retain absolute paths from either platform. The last
    // component must still match the filename the older writer derived.
    if (
      ids.has(canonical) &&
      typeof indexedPath === 'string' &&
      indexedPath.split(/[/\\]/).at(-1) === path.basename(getLegacyEntryPath(storageDir, canonical))
    ) {
      // The index cannot distinguish which spelling last wrote the shared file.
      aliases.set(canonical, aliases.has(canonical) ? null : id)
    }
  }
  return aliases
}

/** A replacement character in a legacy filename is evidence of a record, not its spelling. */
function legacySpelling(
  canonical: string,
  aliases: ReadonlyMap<string, string | null>,
  entryPath: string,
): string {
  if (!canonical.includes('\ufffd')) {
    return canonical
  }
  const id = aliases.get(canonical)
  if (id == null) {
    throw new DecryptionError(
      'Ambiguous YubiKey legacy record ID. Restore its original metadata.',
      entryPath,
    )
  }
  return id
}

/** Reserve a private sibling within the canonical record's path budget, even for `.enc`. */
async function stageRecord(entryPath: string, encrypted: string): Promise<string> {
  const suffixLength = path.basename(entryPath).length - 2
  for (let attempt = 0; attempt < 16; attempt++) {
    const suffix = crypto.randomBytes(12).toString('base64url').slice(0, suffixLength)
    const stage = path.join(path.dirname(entryPath), `.s${suffix}`)
    let file: fs.FileHandle
    try {
      file = await fs.open(stage, 'wx', 0o600)
    } catch (err) {
      if (err instanceof Error && 'code' in err && err.code === 'EEXIST') {
        continue
      }
      throw toFilesystemError(err, 'YubiKey staged entry', stage, 'write')
    }
    try {
      try {
        await file.writeFile(encrypted)
      } finally {
        await file.close()
      }
      return stage
    } catch (err) {
      // Exclusive open succeeded, so only this writer owns the stage.
      await fs.unlink(stage).catch(() => undefined)
      throw toFilesystemError(err, 'YubiKey staged entry', stage, 'write')
    }
  }
  throw new FilesystemError(
    'Could not reserve a YubiKey staging path',
    entryPath,
    'write',
    'EEXIST',
  )
}

/** Publish a complete regular file without opening or mutating the existing directory entry. */
async function publishRecord(entryPath: string, encrypted: string): Promise<void> {
  const stage = await stageRecord(entryPath, encrypted)
  try {
    // The filesystem may retain an older case spelling. Inventory uses the
    // same path as this rename and therefore recognizes that alias.
    await fs.rename(stage, entryPath)
  } catch (err) {
    await fs.unlink(stage).catch(() => undefined)
    throw toFilesystemError(err, 'YubiKey inventory entry', entryPath, 'write')
  }
}

/** Expected byte length of a YubiKey HMAC-SHA1 response (20 bytes = 40 hex chars). */
const HMAC_RESPONSE_HEX_LENGTH = 40

/** Regex for a valid HMAC-SHA1 hex response: exactly 40 lowercase or uppercase hex digits. */
const HMAC_RESPONSE_RE = /^[0-9a-fA-F]{40}$/

/**
 * Derive a 256-bit AES key from the YubiKey HMAC-SHA1 response using HKDF-SHA-256.
 *
 * The HMAC-SHA1 response is 20 bytes — too short and too biased to use
 * directly as an AES-256 key. HKDF expands it to exactly 32 bytes while
 * binding the key to the secret `id` via the `info` field.
 *
 * Throws if `hmacResponse` is not exactly 40 hex characters (20 bytes), which
 * would indicate a malformed or truncated ykman response.
 */
function deriveKey(hmacResponse: string, id: string): Buffer {
  const trimmed = hmacResponse.trim()
  if (!HMAC_RESPONSE_RE.test(trimmed)) {
    throw new SetupError(
      `Invalid YubiKey HMAC response: expected exactly ${String(HMAC_RESPONSE_HEX_LENGTH)} hex characters (20 bytes), got ${String(trimmed.length)} characters`,
      'ykman',
    )
  }
  // The ykman response is a hex string; convert to raw bytes as the IKM.
  const ikm = Buffer.from(trimmed, 'hex')
  const info = Buffer.from(`vaultkeeper-yubikey:${id}`, 'utf8')
  // Node's hkdfSync returns an ArrayBuffer; wrap without copying.
  const keyMaterial = crypto.hkdfSync('sha256', ikm, Buffer.alloc(0), info, GCM_KEY_BYTES)
  return Buffer.from(keyMaterial)
}

/**
 * Encrypt `plaintext` with AES-256-GCM using `key`.
 * Returns a versioned, colon-separated string: `1:<iv>:<authTag>:<ciphertext>`
 * (all binary fields base64-encoded). An explicit spelling is stored and
 * authenticated only when the canonical filename alone is ambiguous.
 *
 * The key and all intermediate buffers are zeroed in the finally block,
 * guaranteeing cleanup even if `createCipheriv` or `cipher.final()` throws.
 */
function encryptGcm(key: Buffer, plaintext: string, identity?: Buffer): string {
  const iv = crypto.randomBytes(GCM_IV_BYTES)
  let encrypted: Buffer | undefined
  let authTag: Buffer | undefined
  try {
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv, {
      authTagLength: GCM_TAG_LENGTH_BITS / 8,
    })
    if (identity !== undefined) {
      cipher.setAAD(identity)
    }
    encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()])
    authTag = cipher.getAuthTag()

    return [
      identity === undefined ? FORMAT_VERSION : IDENTITY_FORMAT_VERSION,
      iv.toString('base64'),
      authTag.toString('base64'),
      encrypted.toString('base64'),
      ...(identity === undefined ? [] : [identity.toString('base64')]),
    ].join(':')
  } finally {
    // Zero all secret material regardless of success or failure.
    key.fill(0)
    iv.fill(0)
    encrypted?.fill(0)
    authTag?.fill(0)
  }
}

/**
 * Decrypt a versioned GCM blob produced by `encryptGcm`.
 *
 * Version detection distinguishes three cases:
 * - First segment matches a supported GCM version → proceed.
 * - First segment is a different number → unsupported future version, throw a
 *   clear "unsupported version N" error.
 * - First segment is not a number at all → legacy/corrupt format (e.g. an
 *   AES-256-CBC file written before this implementation), throw a migration error.
 *
 * The key buffer is always zeroed in a finally block, guaranteeing cleanup even
 * if `createDecipheriv` or `setAuthTag` throws before the decrypt attempt.
 *
 * @param path - The path of the encrypted entry, for attribution on a thrown
 * {@link DecryptionError}.
 */
function decryptGcm(
  key: Buffer,
  encoded: string,
  id: string,
  requiresIdentity: boolean,
  path: string,
): string {
  const parts = encoded.split(':')
  const versionSegment = parts[0] ?? ''

  // Determine whether the first segment is a numeric version prefix at all.
  const parsedVersion = parseInt(versionSegment, 10)
  const isNumericVersion = String(parsedVersion) === versionSegment && !Number.isNaN(parsedVersion)

  if (!isNumericVersion) {
    // No recognisable version prefix — treat as legacy CBC or corrupt file.
    key.fill(0)
    throw new DecryptionError(
      'Encrypted file uses a legacy format (AES-256-CBC). ' +
        'Delete the secret and re-store it to migrate to AES-256-GCM.',
      path,
    )
  }

  const hasIdentity = versionSegment === IDENTITY_FORMAT_VERSION
  if (versionSegment !== FORMAT_VERSION && !hasIdentity) {
    // A future format version this binary does not know how to decode.
    key.fill(0)
    throw new DecryptionError(
      `Unsupported encrypted file version: ${versionSegment}. ` +
        `This vaultkeeper build supports versions ${FORMAT_VERSION} and ${IDENTITY_FORMAT_VERSION}. ` +
        'Upgrade vaultkeeper to read this secret.',
      path,
    )
  }
  if (hasIdentity !== requiresIdentity) {
    key.fill(0)
    throw new DecryptionError('Encrypted file version does not match its record path', path)
  }

  if (parts.length !== (hasIdentity ? 5 : 4)) {
    key.fill(0)
    throw new DecryptionError(`Invalid encrypted file format for version ${versionSegment}`, path)
  }

  const [_version, ivB64, authTagB64, ciphertextB64, identityB64] = parts
  if (ivB64 === undefined || authTagB64 === undefined || ciphertextB64 === undefined) {
    key.fill(0)
    throw new DecryptionError('Invalid encrypted file format: missing part', path)
  }

  let decrypted: Buffer | undefined
  try {
    const identity = identityB64 === undefined ? undefined : decodeIdentity(identityB64)
    if (hasIdentity && identity === undefined) {
      throw new DecryptionError('Invalid encrypted file ID field', path)
    }
    if (identity !== undefined && identity.toString('utf16le') !== id) {
      throw new DecryptionError('Encrypted file ID does not match the requested ID', path)
    }
    const iv = Buffer.from(ivB64, 'base64')
    const authTag = Buffer.from(authTagB64, 'base64')
    const ciphertext = Buffer.from(ciphertextB64, 'base64')

    // createDecipheriv/setAuthTag sit inside this try too: the iv and
    // authTag lengths come from the on-disk file, so a truncated/corrupt
    // entry can throw a native RangeError/TypeError before decryption even
    // starts — every native crypto failure must wrap as DecryptionError.
    try {
      const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv, {
        authTagLength: GCM_TAG_LENGTH_BITS / 8,
      })
      if (identity !== undefined) {
        decipher.setAAD(identity)
      }
      decipher.setAuthTag(authTag)
      decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()])
    } catch (err) {
      throw new DecryptionError(
        `GCM authentication failed — ciphertext may be tampered or corrupt: ${err instanceof Error ? err.message : String(err)}`,
        path,
      )
    }

    const plaintext = decrypted.toString('utf8')
    return plaintext
  } finally {
    // Zero all secret material regardless of success or failure.
    key.fill(0)
    decrypted?.fill(0)
  }
}

/**
 * YubiKey backend via `ykman` CLI.
 *
 * @remarks
 * Requires ykman to be installed and a YubiKey to be connected.
 * Secrets are stored in files encrypted using AES-256-GCM. The encryption
 * key is derived from the YubiKey's HMAC-SHA1 challenge-response (slot 2)
 * via HKDF-SHA-256, binding each secret to its `id`.
 *
 * @internal
 */
export class YubikeyBackend implements ListableBackend, PresenceCapableBackend {
  readonly type = 'yubikey'
  readonly displayName = 'YubiKey'

  readonly #storageDir: string

  /**
   * Whether the configured challenge-response slot enforces a touch for every
   * operation. When `true`, each `store`/`retrieve`/`delete` requires a fresh
   * physical tap (see {@link YubikeyBackend.getCapabilities}). Sourced from
   * configuration, not hardcoded by type — a slot without a touch policy
   * reports `false`.
   */
  readonly #requireTouch: boolean

  /**
   * @param storageDir - Directory in which encrypted secrets and metadata are
   *   stored. Sourced from `BackendConfig.path`. Defaults to
   *   `$HOME/.vaultkeeper/yubikey`.
   * @param requireTouch - Whether the configured challenge-response slot
   *   enforces a touch-per-operation policy. Defaults to `false`. Sourced from
   *   the operator's configuration and must match the physical slot's policy
   *   (verify with `ykman otp info`); it governs the value reported by
   *   {@link YubikeyBackend.getCapabilities}.
   */
  constructor(storageDir?: string, requireTouch = false) {
    this.#storageDir = resolveStorageDir(storageDir)
    this.#requireTouch = requireTouch
  }

  /**
   * Report this instance's capabilities.
   *
   * @remarks
   * `presencePerUse` is `true` only when the configured slot enforces a
   * touch-per-operation policy (`requireTouch`). A slot without a touch
   * policy reports `false`; the answer is never derived from the backend
   * `type` alone. Truth-basis: the reported value comes from the
   * operator-declared `touchPolicy` configuration; confirm it matches the
   * physical slot with `ykman otp info` (a manual verification).
   *
   * **Operation coverage (issue #326):** the touch-per-operation policy only
   * actually fires for {@link YubikeyBackend.store} and
   * {@link YubikeyBackend.retrieve} — both perform the HMAC-SHA1
   * challenge-response (`ykman otp calculate 2 ...`) that demands the
   * physical tap. {@link YubikeyBackend.delete} only calls
   * `requireDevice()` (a presence *probe*: is a YubiKey plugged in at all)
   * plus a filesystem unlink — it never invokes challenge-response, so it
   * never actually demands a fresh touch. Reporting
   * `presenceEnforcedOperations` omitted (meaning "all keyed operations")
   * would therefore be dishonest: a caller relying on `presencePerUse` to
   * mean "deleting this secret requires a physical touch" would be misled.
   * This reports `presenceEnforcedOperations: ['read', 'store']`, excluding
   * `'delete'`, so a `--require-presence-per-use` delete fails closed
   * instead of silently succeeding with no touch. `'sign'` does not apply —
   * this backend does not implement signing.
   */
  getCapabilities(): Promise<BackendCapabilities> {
    if (this.#requireTouch) {
      return Promise.resolve({
        presencePerUse: true,
        presenceEnforcedOperations: ['read', 'store'],
      })
    }
    return Promise.resolve({ presencePerUse: false })
  }

  async isAvailable(): Promise<boolean> {
    try {
      const result = await execCommandFull('ykman', ['--version'])
      if (result.exitCode !== 0) {
        return false
      }
      // Also verify a YubiKey is connected
      const listResult = await execCommandFull('ykman', ['list'])
      return listResult.exitCode === 0 && listResult.stdout.trim() !== ''
    } catch {
      return false
    }
  }

  private async requireDevice(): Promise<void> {
    const available = await this.isAvailable()
    if (!available) {
      const hasYkman = await execCommandFull('ykman', ['--version']).then(
        (r) => r.exitCode === 0,
        () => false,
      )
      if (!hasYkman) {
        throw new PluginNotFoundError('ykman is not installed', 'ykman', YKMAN_INSTALL_URL)
      }
      throw new DeviceNotPresentError('No YubiKey device detected', DEVICE_TIMEOUT_MS)
    }
  }

  /**
   * Perform the YubiKey HMAC-SHA1 challenge-response for `id` and return the
   * raw hex response string. Throws on device failure.
   */
  private async challengeResponse(id: string): Promise<string> {
    const challenge = Buffer.from(`vaultkeeper:${id}`, 'utf8').toString('hex')
    const responseResult = await execCommandFull('ykman', ['otp', 'calculate', '2', challenge])
    if (responseResult.exitCode !== 0) {
      throw new ExecError(`YubiKey challenge-response failed: ${responseResult.stderr}`, 'ykman')
    }
    return responseResult.stdout.trim()
  }

  async store(id: string, secret: string): Promise<void> {
    await this.requireDevice()

    const storageDir = this.#storageDir
    try {
      await fs.mkdir(storageDir, { recursive: true, mode: 0o700 })
    } catch (err) {
      throw toFilesystemError(err, 'YubiKey inventory directory', storageDir, 'write')
    }
    const legacyPath = await this.#legacyEntryPath(id)

    const hmacResponse = await this.challengeResponse(id)
    const key = deriveKey(hmacResponse, id)
    const encrypted = encryptGcm(key, secret, exactIdentity(id))

    await publishRecord(getEntryPath(storageDir, id), encrypted)
    if (legacyPath !== undefined) {
      // Retire the superseded value only after its replacement has been published.
      await this.#deleteEntry(legacyPath)
    }
  }

  async retrieve(id: string): Promise<string> {
    await this.requireDevice()

    const entryPath = await this.#existingEntryPath(id)
    if (entryPath === undefined) {
      throw new SecretNotFoundError(`Secret not found in YubiKey store: ${id}`)
    }

    const encoded = await fs.readFile(entryPath, 'utf8')
    const hmacResponse = await this.challengeResponse(id)
    const key = deriveKey(hmacResponse, id)

    return decryptGcm(
      key,
      encoded,
      id,
      entryPath !== getLegacyEntryPath(this.#storageDir, id),
      entryPath,
    )
  }

  async delete(id: string): Promise<void> {
    await this.requireDevice()

    const entryPath = getEntryPath(this.#storageDir, id)
    const legacyPath = await this.#legacyEntryPath(id)
    // Retire both generations of the same ID so deleting an upgraded record
    // cannot restore an older credential. The legacy path is never written by
    // upgraded ambiguous IDs, so a concurrent store of another spelling wins
    // in its own namespace.
    const deletedLegacy = legacyPath !== undefined && (await this.#deleteEntry(legacyPath))
    if (!(await this.#deleteEntry(entryPath, deletedLegacy)) && !deletedLegacy) {
      throw new SecretNotFoundError(`Secret not found in YubiKey store: ${id}`)
    }
  }

  /** A missing record or an impossible exact path after legacy deletion needs no further cleanup. */
  async #deleteEntry(entryPath: string, deletedLegacy = false): Promise<boolean> {
    try {
      await fs.unlink(entryPath)
      return true
    } catch (err) {
      if (
        err instanceof Error &&
        'code' in err &&
        (err.code === 'ENOENT' || (deletedLegacy && err.code === 'ENAMETOOLONG'))
      ) {
        return false
      }
      throw toFilesystemError(err, 'YubiKey inventory entry', entryPath, 'write')
    }
  }

  /** Prefer the exact path. Legacy records fall back to their recoverable spelling. */
  async #existingEntryPath(id: string): Promise<string | undefined> {
    const entryPath = getEntryPath(this.#storageDir, id)
    try {
      await fs.access(entryPath)
      return entryPath
    } catch {
      return this.#legacyEntryPath(id)
    }
  }

  /** A legacy path may be used only for the spelling recovered by inventory. */
  async #legacyEntryPath(id: string): Promise<string | undefined> {
    const canonical = Buffer.from(id, 'utf8').toString('utf8')
    if (!canonical.includes('\ufffd')) {
      return undefined
    }
    const legacyPath = getLegacyEntryPath(this.#storageDir, canonical)
    const legacyName = path.basename(legacyPath)
    // Enumeration avoids opening a legacy filename that exceeds path limits.
    if (
      !(await this.#listStorageEntries()).some((entry) => entry.name.toLowerCase() === legacyName)
    ) {
      return undefined
    }
    if ((await this.#readInventoryRecord(legacyPath)) !== null) {
      return undefined
    }
    const aliases = await legacyInventoryAliases(this.#storageDir, new Set([canonical]))
    return legacySpelling(canonical, aliases, legacyPath) === id ? legacyPath : undefined
  }

  /** Read through the same canonical path as lookup, including old links to regular files. */
  async #readInventoryRecord(entryPath: string): Promise<string | null | undefined> {
    try {
      if (!(await fs.stat(entryPath)).isFile()) {
        return undefined
      }
      const data = await fs.readFile(entryPath)
      try {
        return inventoryRecordId(data)
      } finally {
        data.fill(0)
      }
    } catch (err) {
      if (
        err instanceof Error &&
        'code' in err &&
        (err.code === 'ENOENT' || err.code === 'ENOTDIR' || err.code === 'ELOOP')
      ) {
        return undefined
      }
      throw toFilesystemError(err, 'YubiKey inventory entry', entryPath, 'read')
    }
  }

  async exists(id: string): Promise<boolean> {
    return (await this.#existingEntryPath(id)) !== undefined
  }

  /** An absent storage directory has no records. Other directory errors need attention. */
  async #listStorageEntries(): Promise<Dirent[]> {
    try {
      return await fs.readdir(this.#storageDir, { withFileTypes: true })
    } catch (err) {
      if (err instanceof Error && 'code' in err && err.code === 'ENOENT') {
        return []
      }
      throw toFilesystemError(err, 'YubiKey inventory directory', this.#storageDir, 'read')
    }
  }

  async list(): Promise<string[]> {
    // Entry files are authoritative: the legacy shared index may be stale.
    const ids = new Set<string>()
    const legacyIds = new Set<string>()
    for (const name of await this.#inventoryNames()) {
      if (!/^(?:[0-9a-f]{2})*\.enc$/.test(name)) {
        continue
      }
      const hex = name.slice(0, -4)
      const id = Buffer.from(hex, 'hex').toString('utf8')
      if (
        Buffer.from(id, 'utf8').toString('hex') === hex &&
        (await this.#readInventoryRecord(path.join(this.#storageDir, name))) === null
      ) {
        legacyIds.add(id)
      }
    }
    const aliasCandidates = new Set([...legacyIds].filter((id) => id.includes('\ufffd')))
    const aliases = await legacyInventoryAliases(this.#storageDir, aliasCandidates)
    for (const id of legacyIds) {
      ids.add(legacySpelling(id, aliases, getLegacyEntryPath(this.#storageDir, id)))
    }

    // Exact replacements are published before their legacy files are retired.
    // Enumerate exact names after reading legacy records so a migration cannot fall between scans.
    for (const name of await this.#inventoryNames()) {
      if (!/^id-[0-9a-f]{64}\.enc$/.test(name)) {
        continue
      }
      const entryPath = path.join(this.#storageDir, name)
      const spelling = await this.#readInventoryRecord(entryPath)
      if (typeof spelling === 'string' && getEntryPath(this.#storageDir, spelling) === entryPath) {
        ids.add(spelling)
      }
    }
    return [...ids]
  }

  /** Fold names to the spelling lookup uses. The subsequent read confirms filesystem reachability. */
  async #inventoryNames(): Promise<Set<string>> {
    const entries = await this.#listStorageEntries()
    return new Set(
      entries
        .filter((entry) => entry.isFile() || entry.isSymbolicLink())
        .map((entry) => entry.name.toLowerCase()),
    )
  }
}
