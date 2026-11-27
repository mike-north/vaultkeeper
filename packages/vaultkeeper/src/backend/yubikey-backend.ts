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

/** The hashed spelling bounds filename length for IDs whose encoded bytes are long. */
function hashedEntryName(identity: Buffer): string {
  return `id-${crypto.createHash('sha256').update(identity).digest('hex')}.enc`
}

/**
 * Hex-encoded WTF-8 keeps the same path budget as the old UTF-8 filename.
 * A lone surrogate uses its own three-byte encoding, while scalar values use UTF-8.
 * The separate extension prevents an exact record from taking a legacy path.
 */
function compactEntryName(id: string): string {
  const hex = Array.from(id, (character) => {
    const unit = character.charCodeAt(0)
    if (character.length === 1 && unit >= 0xd800 && unit <= 0xdfff) {
      return Buffer.from([0xed, 0x80 | ((unit >> 6) & 0x3f), 0x80 | (unit & 0x3f)]).toString('hex')
    }
    return Buffer.from(character, 'utf8').toString('hex')
  }).join('')
  return `${hex}.vk2`
}

/** Validate the canonical WTF-8 spelling before resolving a compact filename. */
function compactRecordId(name: string): string | undefined {
  if (!/^(?:[0-9a-f]{2}){3,33}\.vk2$/.test(name)) {
    return undefined
  }
  const encoded = Buffer.from(name.slice(0, -4), 'hex').toString('latin1')
  const id = encoded
    .split(/(\xed[\xa0-\xbf][\x80-\xbf])/)
    .map((part, index) => {
      if (index % 2 === 0) {
        return Buffer.from(part, 'latin1').toString('utf8')
      }
      // ED supplies the top four bits for a surrogate encoded as three UTF-8 bytes.
      return String.fromCharCode(
        0xd000 | ((part.charCodeAt(1) & 0x3f) << 6) | (part.charCodeAt(2) & 0x3f),
      )
    })
    .join('')
  return exactIdentity(id) !== undefined && compactEntryName(id) === name ? id : undefined
}

/** Choose one exact path by filename length so alternate paths to a directory agree. */
function getEntryPath(storageDir: string, id: string): string {
  const identity = exactIdentity(id)
  if (identity === undefined) {
    return getLegacyEntryPath(storageDir, id)
  }
  const compact = compactEntryName(id)
  const hashed = hashedEntryName(identity)
  return path.join(storageDir, compact.length < hashed.length ? compact : hashed)
}

/** Earlier exact records always used a hash, even for short spellings. */
function olderExactEntryPath(storageDir: string, id: string): string | undefined {
  const identity = exactIdentity(id)
  if (identity !== undefined && getEntryPath(storageDir, id).endsWith('.vk2')) {
    return path.join(storageDir, hashedEntryName(identity))
  }
  return undefined
}

/** Decode the byte-preserving ID field without letting permissive Base64 rewrite its value. */
function decodeIdentity(encoded: string): Buffer | undefined {
  const identity = Buffer.from(encoded, 'base64')
  return identity.length > 0 && identity.length % 2 === 0 && identity.toString('base64') === encoded
    ? identity
    : undefined
}

/** Preserve ownership evidence even when the exact envelope is truncated. */
function hasExactEnvelope(entry: Buffer): boolean {
  return entry[0] === IDENTITY_FORMAT_VERSION.charCodeAt(0) && entry[1] === 0x3a
}

/** Identify legacy YubiKey envelopes even when another backend uses the same filenames. */
function isLegacyEnvelope(entry: Buffer): boolean {
  if (entry.subarray(0, LEGACY_OPENSSL_MAGIC.length).equals(LEGACY_OPENSSL_MAGIC)) {
    return true
  }
  // A v1 marker survives truncation and cannot be a FileBackend's 12-byte IV.
  if (entry[0] === FORMAT_VERSION.charCodeAt(0) && entry[1] === 0x3a) {
    return true
  }
  const separator = 0x3a
  const versionEnd = entry.indexOf(separator)
  if (
    versionEnd <= 0 ||
    hasExactEnvelope(entry) ||
    !entry.subarray(0, versionEnd).every((byte) => byte >= 0x30 && byte <= 0x39)
  ) {
    return false
  }
  const ivEnd = entry.indexOf(separator, versionEnd + 1)
  const tagEnd = ivEnd === -1 ? -1 : entry.indexOf(separator, ivEnd + 1)
  // A FileBackend envelope has only three fields.
  return tagEnd !== -1 && entry.indexOf(separator, tagEnd + 1) === -1
}

/** A hash cannot recover an ID by itself. Confirm the stored spelling before listing it. */
function hashedInventoryRecordId(entry: Buffer, entryPath: string): string | undefined {
  if (!hasExactEnvelope(entry)) {
    return undefined
  }
  const separator = 0x3a
  const ivEnd = entry.indexOf(separator, 2)
  const tagEnd = ivEnd === -1 ? -1 : entry.indexOf(separator, ivEnd + 1)
  const ciphertextEnd = tagEnd === -1 ? -1 : entry.indexOf(separator, tagEnd + 1)
  if (ciphertextEnd !== -1) {
    const identity = decodeIdentity(entry.subarray(ciphertextEnd + 1).toString('latin1'))
    if (identity !== undefined && hashedEntryName(identity) === path.basename(entryPath)) {
      const id = identity.toString('utf16le')
      if (exactIdentity(id) !== undefined) {
        return id
      }
    }
  }
  throw new DecryptionError('Cannot identify the YubiKey hashed record.', entryPath)
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
    const olderPath = await this.#olderPathForRetirement(id)

    const hmacResponse = await this.challengeResponse(id)
    const encrypted = encryptGcm(deriveKey(hmacResponse, id), secret, exactIdentity(id))

    await publishRecord(getEntryPath(storageDir, id), encrypted)
    if (legacyPath !== undefined) {
      // Retire the superseded value only after its replacement has been published.
      await this.#deleteEntry(legacyPath)
    }
    if (olderPath !== undefined) {
      await this.#deleteEntry(olderPath, true)
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
    const olderPath = await this.#olderPathForRetirement(id)
    // Retire both generations of the same ID so deleting an upgraded record
    // cannot restore an older credential. A store of another spelling uses
    // its own exact path and cannot overwrite this confirmed legacy record.
    const deletedLegacy = legacyPath !== undefined && (await this.#deleteEntry(legacyPath))
    const deletedOlder = olderPath !== undefined && (await this.#deleteEntry(olderPath, true))
    if (!(await this.#deleteEntry(entryPath, deletedLegacy)) && !deletedLegacy && !deletedOlder) {
      throw new SecretNotFoundError(`Secret not found in YubiKey store: ${id}`)
    }
  }

  /** Check for an older hash before modifying any generation of the record. */
  async #olderPathForRetirement(id: string): Promise<string | undefined> {
    const olderPath = olderExactEntryPath(this.#storageDir, id)
    if (olderPath !== undefined) {
      try {
        await fs.lstat(olderPath)
      } catch (err) {
        if (
          !(
            err instanceof Error &&
            'code' in err &&
            (err.code === 'ENOENT' ||
              (err.code === 'ENAMETOOLONG' && !(await this.#hasEntryName(olderPath))))
          )
        ) {
          throw toFilesystemError(err, 'older YubiKey record', olderPath, 'write')
        }
      }
    }
    return olderPath
  }

  /** An overlong path confirms absence only when the filename is also absent from the directory. */
  async #deleteEntry(entryPath: string, allowOverlong = false): Promise<boolean> {
    try {
      await fs.unlink(entryPath)
      return true
    } catch (err) {
      if (
        err instanceof Error &&
        'code' in err &&
        (err.code === 'ENOENT' ||
          (allowOverlong && err.code === 'ENAMETOOLONG' && !(await this.#hasEntryName(entryPath))))
      ) {
        return false
      }
      throw toFilesystemError(err, 'YubiKey inventory entry', entryPath, 'write')
    }
  }

  /** Prefer the exact path. Legacy records fall back to their recoverable spelling. */
  async #existingEntryPath(id: string): Promise<string | undefined> {
    const entryPath = getEntryPath(this.#storageDir, id)
    const olderPath = olderExactEntryPath(this.#storageDir, id)
    return (
      (await this.#accessibleEntryPath(entryPath)) ??
      (olderPath === undefined ? undefined : await this.#accessibleEntryPath(olderPath)) ??
      (await this.#legacyEntryPath(id))
    )
  }

  /** An exact entry can be used only if its path is reachable. */
  async #accessibleEntryPath(entryPath: string): Promise<string | undefined> {
    try {
      await fs.access(entryPath)
      return entryPath
    } catch (err) {
      if (
        err instanceof Error &&
        'code' in err &&
        err.code === 'ENAMETOOLONG' &&
        (await this.#hasEntryName(entryPath))
      ) {
        throw toFilesystemError(err, 'YubiKey record', entryPath, 'read')
      }
      return undefined
    }
  }

  /** An overlong lookup path can still name an entry created through a shorter directory path. */
  async #hasEntryName(entryPath: string): Promise<boolean> {
    const filename = path.basename(entryPath)
    return (await this.#listStorageEntries()).some((entry) => entry.name.toLowerCase() === filename)
  }

  /** A legacy path may be used only for the spelling recovered by inventory. */
  async #legacyEntryPath(id: string): Promise<string | undefined> {
    const canonical = Buffer.from(id, 'utf8').toString('utf8')
    if (!canonical.includes('\ufffd')) {
      return undefined
    }
    const legacyPath = getLegacyEntryPath(this.#storageDir, canonical)
    // Enumeration avoids opening a legacy filename that exceeds path limits.
    if (!(await this.#hasEntryName(legacyPath))) {
      return undefined
    }
    if (!(await this.#readInventoryRecord(legacyPath, isLegacyEnvelope))) {
      return undefined
    }
    const aliases = await legacyInventoryAliases(this.#storageDir, new Set([canonical]))
    return legacySpelling(canonical, aliases, legacyPath) === id ? legacyPath : undefined
  }

  /** Inspect only reachable regular files and keep format errors distinct from I/O errors. */
  async #readInventoryRecord<T>(
    entryPath: string,
    inspect: (entry: Buffer) => T,
  ): Promise<T | undefined> {
    let data: Buffer
    try {
      if (!(await fs.stat(entryPath)).isFile()) {
        return undefined
      }
      data = await fs.readFile(entryPath)
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
    try {
      return inspect(data)
    } finally {
      data.fill(0)
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
        (await this.#readInventoryRecord(path.join(this.#storageDir, name), isLegacyEnvelope))
      ) {
        legacyIds.add(id)
      }
    }
    const aliasCandidates = new Set([...legacyIds].filter((id) => id.includes('\ufffd')))
    const aliases = await legacyInventoryAliases(this.#storageDir, aliasCandidates)
    for (const id of legacyIds) {
      ids.add(legacySpelling(id, aliases, getLegacyEntryPath(this.#storageDir, id)))
    }

    // Scan each layout after its predecessors. Publication always precedes retirement.
    for (const name of await this.#inventoryNames()) {
      if (!/^id-[0-9a-f]{64}\.enc$/.test(name)) {
        continue
      }
      const entryPath = path.join(this.#storageDir, name)
      const spelling = await this.#readInventoryRecord(entryPath, (entry) =>
        hashedInventoryRecordId(entry, entryPath),
      )
      if (spelling !== undefined) {
        ids.add(spelling)
      }
    }
    for (const name of await this.#inventoryNames()) {
      const compactId = compactRecordId(name)
      if (
        compactId !== undefined &&
        (await this.#readInventoryRecord(path.join(this.#storageDir, name), hasExactEnvelope))
      ) {
        ids.add(compactId)
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
