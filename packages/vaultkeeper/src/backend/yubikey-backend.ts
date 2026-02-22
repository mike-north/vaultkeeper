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
 * The leading "1:" version prefix allows future format migrations and enables
 * detection of legacy CBC files (which lack this prefix).
 */

import * as fs from 'node:fs/promises'
import * as path from 'node:path'
import * as os from 'node:os'
import * as crypto from 'node:crypto'
import { execCommandFull } from '../util/exec.js'
import { SecretNotFoundError, PluginNotFoundError, DeviceNotPresentError } from '../errors.js'
import type { SecretBackend } from './types.js'

const YKMAN_INSTALL_URL = 'https://developers.yubico.com/yubikey-manager/'
const STORAGE_DIR_NAME = path.join('.vaultkeeper', 'yubikey')
const METADATA_FILE = 'metadata.json'
const DEVICE_TIMEOUT_MS = 5000

/** AES-256-GCM constants */
const GCM_IV_BYTES = 12
const GCM_KEY_BYTES = 32
const GCM_TAG_LENGTH_BITS = 128

/** Version prefix written at the start of every encrypted file. */
const FORMAT_VERSION = '1'

interface YubikeyMetadata {
  entries: Record<string, string>
}

function getStorageDir(): string {
  return path.join(os.homedir(), STORAGE_DIR_NAME)
}

function getEntryPath(storageDir: string, id: string): string {
  const safeId = Buffer.from(id, 'utf8').toString('hex')
  return path.join(storageDir, `${safeId}.enc`)
}

function isStringRecord(value: unknown): value is Record<string, string> {
  if (value === null || typeof value !== 'object') {
    return false
  }
  return Object.values(value).every((v) => typeof v === 'string')
}

async function loadMetadata(storageDir: string): Promise<YubikeyMetadata> {
  const metaPath = path.join(storageDir, METADATA_FILE)
  try {
    const raw = await fs.readFile(metaPath, 'utf8')
    const parsed: unknown = JSON.parse(raw)
    if (
      parsed !== null &&
      typeof parsed === 'object' &&
      'entries' in parsed &&
      isStringRecord(parsed.entries)
    ) {
      return { entries: parsed.entries }
    }
    return { entries: {} }
  } catch {
    return { entries: {} }
  }
}

async function saveMetadata(storageDir: string, metadata: YubikeyMetadata): Promise<void> {
  const metaPath = path.join(storageDir, METADATA_FILE)
  await fs.writeFile(metaPath, JSON.stringify(metadata, null, 2), { mode: 0o600 })
}

/**
 * Derive a 256-bit AES key from the YubiKey HMAC-SHA1 response using HKDF-SHA-256.
 *
 * The HMAC-SHA1 response is 20 bytes — too short and too biased to use
 * directly as an AES-256 key. HKDF expands it to exactly 32 bytes while
 * binding the key to the secret `id` via the `info` field.
 */
function deriveKey(hmacResponse: string, id: string): Buffer {
  // The ykman response is a hex string; convert to raw bytes as the IKM.
  const ikm = Buffer.from(hmacResponse, 'hex')
  const info = Buffer.from(`vaultkeeper-yubikey:${id}`, 'utf8')
  // Node's hkdfSync returns an ArrayBuffer; wrap without copying.
  const keyMaterial = crypto.hkdfSync('sha256', ikm, Buffer.alloc(0), info, GCM_KEY_BYTES)
  return Buffer.from(keyMaterial)
}

/**
 * Encrypt `plaintext` with AES-256-GCM using `key`.
 * Returns a versioned, colon-separated string: `1:<iv>:<authTag>:<ciphertext>`
 * (all binary fields base64-encoded).
 */
function encryptGcm(key: Buffer, plaintext: string): string {
  const iv = crypto.randomBytes(GCM_IV_BYTES)
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv, {
    authTagLength: GCM_TAG_LENGTH_BITS / 8,
  })
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()])
  const authTag = cipher.getAuthTag()

  const encoded = [
    FORMAT_VERSION,
    iv.toString('base64'),
    authTag.toString('base64'),
    encrypted.toString('base64'),
  ].join(':')

  // Zero the key buffer now that encryption is complete.
  key.fill(0)

  return encoded
}

/**
 * Decrypt a versioned GCM blob produced by `encryptGcm`.
 * Throws a descriptive error if the format is unrecognized (e.g. a legacy
 * AES-256-CBC file created before this fix was applied).
 */
function decryptGcm(key: Buffer, encoded: string): string {
  const parts = encoded.split(':')

  // A legacy CBC file (openssl enc output) is binary and will not match our
  // version prefix pattern. Detect and surface a clear migration error rather
  // than a confusing crypto failure.
  if (parts[0] !== FORMAT_VERSION) {
    key.fill(0)
    throw new Error(
      'Encrypted file uses a legacy format (AES-256-CBC). ' +
        'Delete the secret and re-store it to migrate to AES-256-GCM.',
    )
  }

  if (parts.length !== 4) {
    key.fill(0)
    throw new Error(
      `Invalid encrypted file format: expected ${FORMAT_VERSION}:iv:authTag:ciphertext`,
    )
  }

  const [_version, ivB64, authTagB64, ciphertextB64] = parts
  if (ivB64 === undefined || authTagB64 === undefined || ciphertextB64 === undefined) {
    key.fill(0)
    throw new Error('Invalid encrypted file format: missing part')
  }

  const iv = Buffer.from(ivB64, 'base64')
  const authTag = Buffer.from(authTagB64, 'base64')
  const ciphertext = Buffer.from(ciphertextB64, 'base64')

  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv, {
    authTagLength: GCM_TAG_LENGTH_BITS / 8,
  })
  decipher.setAuthTag(authTag)

  let decrypted: Buffer
  try {
    decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()])
  } catch (err) {
    key.fill(0)
    throw new Error(
      `GCM authentication failed — ciphertext may be tampered: ${err instanceof Error ? err.message : String(err)}`,
    )
  }

  const plaintext = decrypted.toString('utf8')
  // Zero the key and decrypted buffers now that we have the string.
  key.fill(0)
  decrypted.fill(0)
  return plaintext
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
export class YubikeyBackend implements SecretBackend {
  readonly type = 'yubikey'
  readonly displayName = 'YubiKey'

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
      throw new Error(`YubiKey challenge-response failed: ${responseResult.stderr}`)
    }
    return responseResult.stdout.trim()
  }

  async store(id: string, secret: string): Promise<void> {
    await this.requireDevice()

    const storageDir = getStorageDir()
    await fs.mkdir(storageDir, { recursive: true, mode: 0o700 })

    const hmacResponse = await this.challengeResponse(id)
    const key = deriveKey(hmacResponse, id)
    const encrypted = encryptGcm(key, secret)

    const entryPath = getEntryPath(storageDir, id)
    await fs.writeFile(entryPath, encrypted, { mode: 0o600 })

    const metadata = await loadMetadata(storageDir)
    metadata.entries[id] = entryPath
    await saveMetadata(storageDir, metadata)
  }

  async retrieve(id: string): Promise<string> {
    await this.requireDevice()

    const storageDir = getStorageDir()
    const entryPath = getEntryPath(storageDir, id)

    try {
      await fs.access(entryPath)
    } catch {
      throw new SecretNotFoundError(`Secret not found in YubiKey store: ${id}`)
    }

    const encoded = await fs.readFile(entryPath, 'utf8')
    const hmacResponse = await this.challengeResponse(id)
    const key = deriveKey(hmacResponse, id)

    return decryptGcm(key, encoded)
  }

  async delete(id: string): Promise<void> {
    await this.requireDevice()

    const storageDir = getStorageDir()
    const entryPath = getEntryPath(storageDir, id)

    try {
      await fs.unlink(entryPath)
    } catch (err) {
      if (err instanceof Error && 'code' in err && err.code === 'ENOENT') {
        throw new SecretNotFoundError(`Secret not found in YubiKey store: ${id}`)
      }
      throw err
    }

    const metadata = await loadMetadata(storageDir)
    // eslint-disable-next-line @typescript-eslint/no-dynamic-delete
    delete metadata.entries[id]
    await saveMetadata(storageDir, metadata)
  }

  async exists(id: string): Promise<boolean> {
    const storageDir = getStorageDir()
    const entryPath = getEntryPath(storageDir, id)

    try {
      await fs.access(entryPath)
      return true
    } catch {
      return false
    }
  }
}
