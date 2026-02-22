/**
 * Encrypted file fallback backend implementation.
 *
 * @remarks
 * Stores secrets encrypted with AES-256-GCM using Node.js native crypto.
 * Each secret is stored as an individual encrypted file under
 * ~/.vaultkeeper/file/. A randomly generated key stored in a protected
 * file is used for encryption.
 *
 * Encrypted file format (all parts base64-encoded, colon-separated):
 *   <iv>:<authTag>:<ciphertext>
 */

import * as fs from 'node:fs/promises'
import * as path from 'node:path'
import * as os from 'node:os'
import * as crypto from 'node:crypto'
import { SecretNotFoundError, FilesystemError } from '../errors.js'
import type { SecretBackend } from './types.js'

const STORAGE_DIR_NAME = path.join('.vaultkeeper', 'file')
const KEY_FILE = '.key'
const GCM_IV_BYTES = 12
const GCM_KEY_BYTES = 32
const GCM_TAG_LENGTH = 128 // bits

function getStorageDir(): string {
  return path.join(os.homedir(), STORAGE_DIR_NAME)
}

function getEntryPath(storageDir: string, id: string): string {
  const safeId = Buffer.from(id, 'utf8').toString('hex')
  return path.join(storageDir, `${safeId}.enc`)
}

async function ensureStorageDir(storageDir: string): Promise<void> {
  try {
    await fs.mkdir(storageDir, { recursive: true, mode: 0o700 })
  } catch (err) {
    if (err instanceof Error && 'code' in err && err.code !== 'EEXIST') {
      throw new FilesystemError(
        `Failed to create storage directory: ${storageDir}`,
        storageDir,
        'rwx',
      )
    }
  }
}

async function getOrCreateKey(storageDir: string): Promise<Buffer> {
  const keyPath = path.join(storageDir, KEY_FILE)
  try {
    const data = await fs.readFile(keyPath)
    return data
  } catch (err) {
    if (err instanceof Error && 'code' in err && err.code === 'ENOENT') {
      // Generate a random 32-byte key
      const key = crypto.randomBytes(GCM_KEY_BYTES)
      await fs.writeFile(keyPath, key, { mode: 0o600 })
      return key
    }
    throw err
  }
}

function encryptGcm(key: Buffer, plaintext: string): string {
  const iv = crypto.randomBytes(GCM_IV_BYTES)
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv, {
    authTagLength: GCM_TAG_LENGTH / 8,
  })
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()])
  const authTag = cipher.getAuthTag()
  return [iv.toString('base64'), authTag.toString('base64'), encrypted.toString('base64')].join(':')
}

function decryptGcm(key: Buffer, encoded: string): string {
  const parts = encoded.split(':')
  if (parts.length !== 3) {
    throw new Error('Invalid encrypted file format: expected iv:authTag:ciphertext')
  }
  const [ivB64, authTagB64, ciphertextB64] = parts
  if (ivB64 === undefined || authTagB64 === undefined || ciphertextB64 === undefined) {
    throw new Error('Invalid encrypted file format: missing part')
  }
  const iv = Buffer.from(ivB64, 'base64')
  const authTag = Buffer.from(authTagB64, 'base64')
  const ciphertext = Buffer.from(ciphertextB64, 'base64')

  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv, {
    authTagLength: GCM_TAG_LENGTH / 8,
  })
  decipher.setAuthTag(authTag)
  const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()])
  return decrypted.toString('utf8')
}

/**
 * Encrypted file fallback backend.
 *
 * @remarks
 * Available on all platforms. Stores secrets as AES-256-GCM encrypted files
 * using Node.js native crypto — no external tools required.
 * Not as secure as OS-native keystores, but provides a portable fallback.
 *
 * @internal
 */
export class FileBackend implements SecretBackend {
  readonly type = 'file'
  readonly displayName = 'Encrypted File Store'

  async isAvailable(): Promise<boolean> {
    // Node.js crypto is always available; check we can create the storage dir.
    try {
      const storageDir = getStorageDir()
      await ensureStorageDir(storageDir)
      return true
    } catch {
      return false
    }
  }

  async store(id: string, secret: string): Promise<void> {
    const storageDir = getStorageDir()
    await ensureStorageDir(storageDir)
    const key = await getOrCreateKey(storageDir)
    const entryPath = getEntryPath(storageDir, id)
    const encrypted = encryptGcm(key, secret)
    await fs.writeFile(entryPath, encrypted, { mode: 0o600 })
  }

  async retrieve(id: string): Promise<string> {
    const storageDir = getStorageDir()
    const entryPath = getEntryPath(storageDir, id)

    let encoded: string
    try {
      encoded = await fs.readFile(entryPath, 'utf8')
    } catch (err) {
      if (err instanceof Error && 'code' in err && err.code === 'ENOENT') {
        throw new SecretNotFoundError(`Secret not found in file store: ${id}`)
      }
      throw err
    }

    const key = await getOrCreateKey(storageDir)
    try {
      return decryptGcm(key, encoded)
    } catch (err) {
      throw new Error(
        `Failed to decrypt secret: ${err instanceof Error ? err.message : String(err)}`,
      )
    }
  }

  async delete(id: string): Promise<void> {
    const storageDir = getStorageDir()
    const entryPath = getEntryPath(storageDir, id)

    try {
      await fs.unlink(entryPath)
    } catch (err) {
      if (err instanceof Error && 'code' in err && err.code === 'ENOENT') {
        throw new SecretNotFoundError(`Secret not found in file store: ${id}`)
      }
      throw err
    }
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
