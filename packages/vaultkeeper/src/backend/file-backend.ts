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
import { SecretNotFoundError, FilesystemError } from '../errors.js'
import { encryptGcm, decryptGcm, getOrCreateWrapKey } from '../util/at-rest.js'
import type { ListableBackend } from './types.js'

const STORAGE_DIR_NAME = path.join('.vaultkeeper', 'file')
const KEY_FILE = '.key'

/**
 * Resolve the storage directory for a FileBackend instance.
 *
 * When `configuredPath` is provided (from `BackendConfig.path`), secrets are
 * stored directly under that directory. Otherwise the default
 * `$HOME/.vaultkeeper/file` location is used.
 */
function resolveStorageDir(configuredPath?: string): string {
  // Config validation (see validateConfig) rejects empty/whitespace-only
  // paths, so any defined value here is guaranteed non-blank.
  if (configuredPath !== undefined) {
    return configuredPath
  }
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
  return getOrCreateWrapKey(path.join(storageDir, KEY_FILE))
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
export class FileBackend implements ListableBackend {
  readonly type = 'file'
  readonly displayName = 'Encrypted File Store'

  readonly #storageDir: string

  /**
   * @param storageDir - Directory in which encrypted secrets are stored.
   *   Sourced from `BackendConfig.path`. Defaults to `$HOME/.vaultkeeper/file`.
   */
  constructor(storageDir?: string) {
    this.#storageDir = resolveStorageDir(storageDir)
  }

  async isAvailable(): Promise<boolean> {
    // Node.js crypto is always available; check we can create the storage dir.
    try {
      await ensureStorageDir(this.#storageDir)
      return true
    } catch {
      return false
    }
  }

  async store(id: string, secret: string): Promise<void> {
    const storageDir = this.#storageDir
    await ensureStorageDir(storageDir)
    const key = await getOrCreateKey(storageDir)
    const entryPath = getEntryPath(storageDir, id)
    const encrypted = encryptGcm(key, secret)
    await fs.writeFile(entryPath, encrypted, { mode: 0o600 })
  }

  async retrieve(id: string): Promise<string> {
    const storageDir = this.#storageDir
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
    const storageDir = this.#storageDir
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
    const storageDir = this.#storageDir
    const entryPath = getEntryPath(storageDir, id)

    try {
      await fs.access(entryPath)
      return true
    } catch {
      return false
    }
  }

  async list(): Promise<string[]> {
    const storageDir = this.#storageDir
    let entries: string[]
    try {
      entries = await fs.readdir(storageDir)
    } catch {
      return []
    }
    return entries
      .filter((f) => f.endsWith('.enc'))
      .map((f) => Buffer.from(f.slice(0, -4), 'hex').toString('utf8'))
  }
}
