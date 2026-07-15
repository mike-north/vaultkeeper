/**
 * Encrypted file fallback backend implementation.
 *
 * @remarks
 * Stores secrets encrypted with AES-256-GCM using Node.js native crypto.
 * Each secret is stored as an individual encrypted file under
 * `<configDir>/file/`, where `configDir` is the same resolved config
 * directory used for the config file and key material (see
 * {@link getDefaultConfigDir}). A randomly generated key stored in a
 * protected file is used for encryption.
 *
 * Encrypted file format (all parts base64-encoded, colon-separated):
 *   <iv>:<authTag>:<ciphertext>
 *
 * @remarks Back-compat (issue #99)
 * Prior to this fix, the default storage directory was
 * `$HOME/.vaultkeeper/file`, independent of the resolved config directory.
 * When no explicit `path` is configured, reads (`retrieve`/`exists`/`delete`/
 * `list`) transparently fall back to that legacy location if an entry is not
 * found under the new default, so secrets stored there before this change
 * remain reachable. Writes (`store`) always target the new location — the
 * legacy directory is never written to going forward.
 */

import * as fs from 'node:fs/promises'
import * as path from 'node:path'
import * as os from 'node:os'
import {
  SecretNotFoundError,
  FilesystemError,
  DecryptionError,
  toFilesystemError,
} from '../errors.js'
import { encryptGcm, decryptGcm, getOrCreateWrapKey } from '../util/at-rest.js'
import { getDefaultConfigDir } from '../config.js'
import type { ListableBackend } from './types.js'

const STORAGE_DIR_NAME = 'file'
const KEY_FILE = '.key'

/**
 * Pre-#99 default storage directory, kept as a read-only fallback.
 *
 * @remarks
 * Computed lazily (not as a module-level constant) so it reflects
 * `os.homedir()` at construction time rather than at module load time —
 * matching the existing lazy-resolution pattern the rest of this module
 * relies on for testability.
 */
function legacyStorageDir(): string {
  return path.join(os.homedir(), '.vaultkeeper', 'file')
}

/**
 * Resolve the storage directory for a FileBackend instance.
 *
 * When `configuredPath` is provided (from `BackendConfig.path`), secrets are
 * stored directly under that directory. Otherwise the default is
 * `<configDir>/file`, where `configDir` is the resolved config directory
 * (the value passed to the backend factory, or `getDefaultConfigDir()` when
 * constructing a `FileBackend` directly without one).
 */
function resolveStorageDir(configuredPath?: string, configDir?: string): string {
  // Config validation (see validateConfig) rejects empty/whitespace-only
  // paths, so any defined value here is guaranteed non-blank.
  if (configuredPath !== undefined) {
    return configuredPath
  }
  return path.join(configDir ?? getDefaultConfigDir(), STORAGE_DIR_NAME)
}

function getEntryPath(storageDir: string, id: string): string {
  const safeId = Buffer.from(id, 'utf8').toString('hex')
  return path.join(storageDir, `${safeId}.enc`)
}

async function ensureStorageDir(storageDir: string): Promise<void> {
  try {
    await fs.mkdir(storageDir, { recursive: true, mode: 0o700 })
  } catch (err) {
    // With `recursive: true`, mkdir never throws EEXIST for a directory that
    // already exists — that case resolves silently. An EEXIST here means
    // `storageDir` itself already exists as something other than a
    // directory (e.g. a regular file), a genuine collision that must
    // surface rather than be swallowed as if the directory were ready.
    throw new FilesystemError(
      `Failed to create storage directory: ${storageDir}`,
      storageDir,
      'rwx',
      err,
    )
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
   * Pre-#99 default storage directory, consulted as a read-only fallback
   * when `storageDir` was not explicitly configured. `undefined` when an
   * explicit `storageDir` was given — an explicit path never falls back.
   */
  readonly #legacyStorageDir: string | undefined

  /**
   * @param storageDir - Directory in which encrypted secrets are stored.
   *   Sourced from `BackendConfig.path`. Defaults to `<configDir>/file`.
   * @param configDir - Resolved config directory, used to compute the
   *   default `storageDir` when one is not explicitly provided. Ignored when
   *   `storageDir` is given. Defaults to `getDefaultConfigDir()`.
   */
  constructor(storageDir?: string, configDir?: string) {
    this.#storageDir = resolveStorageDir(storageDir, configDir)
    this.#legacyStorageDir = storageDir === undefined ? legacyStorageDir() : undefined
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
    try {
      await fs.writeFile(entryPath, encrypted, { mode: 0o600 })
    } catch (err) {
      throw toFilesystemError(err, 'secret file', entryPath, 'write')
    }
  }

  /**
   * Attempt to read and decrypt the entry for `id` from `storageDir`.
   * Returns `undefined` (rather than throwing) when the entry does not
   * exist in `storageDir`, so callers can probe a fallback location.
   */
  async #tryRetrieveFrom(storageDir: string, id: string): Promise<string | undefined> {
    const entryPath = getEntryPath(storageDir, id)

    let encoded: string
    try {
      encoded = await fs.readFile(entryPath, 'utf8')
    } catch (err) {
      if (err instanceof Error && 'code' in err && err.code === 'ENOENT') {
        return undefined
      }
      throw toFilesystemError(err, 'secret file', entryPath, 'read')
    }

    const key = await getOrCreateKey(storageDir)
    try {
      return decryptGcm(key, encoded)
    } catch (err) {
      throw new DecryptionError(
        `Failed to decrypt secret: ${err instanceof Error ? err.message : String(err)}`,
        entryPath,
      )
    }
  }

  async retrieve(id: string): Promise<string> {
    const fromPrimary = await this.#tryRetrieveFrom(this.#storageDir, id)
    if (fromPrimary !== undefined) {
      return fromPrimary
    }

    if (this.#legacyStorageDir !== undefined) {
      const fromLegacy = await this.#tryRetrieveFrom(this.#legacyStorageDir, id)
      if (fromLegacy !== undefined) {
        return fromLegacy
      }
    }

    throw new SecretNotFoundError(`Secret not found in file store: ${id}`)
  }

  async delete(id: string): Promise<void> {
    const entryPath = getEntryPath(this.#storageDir, id)

    try {
      await fs.unlink(entryPath)
      return
    } catch (err) {
      if (!(err instanceof Error && 'code' in err && err.code === 'ENOENT')) {
        throw toFilesystemError(err, 'secret file', entryPath, 'delete')
      }
    }

    if (this.#legacyStorageDir !== undefined) {
      const legacyEntryPath = getEntryPath(this.#legacyStorageDir, id)
      try {
        await fs.unlink(legacyEntryPath)
        return
      } catch (err) {
        if (!(err instanceof Error && 'code' in err && err.code === 'ENOENT')) {
          throw toFilesystemError(err, 'secret file', legacyEntryPath, 'delete')
        }
      }
    }

    throw new SecretNotFoundError(`Secret not found in file store: ${id}`)
  }

  async exists(id: string): Promise<boolean> {
    if (await FileBackend.#entryExists(this.#storageDir, id)) {
      return true
    }
    if (this.#legacyStorageDir !== undefined) {
      return FileBackend.#entryExists(this.#legacyStorageDir, id)
    }
    return false
  }

  static async #entryExists(storageDir: string, id: string): Promise<boolean> {
    try {
      await fs.access(getEntryPath(storageDir, id))
      return true
    } catch {
      return false
    }
  }

  async list(): Promise<string[]> {
    const ids = new Set<string>()
    for (const storageDir of [this.#storageDir, this.#legacyStorageDir].filter(
      (dir): dir is string => dir !== undefined,
    )) {
      for (const id of await FileBackend.#listEntries(storageDir)) {
        ids.add(id)
      }
    }
    return Array.from(ids)
  }

  static async #listEntries(storageDir: string): Promise<string[]> {
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
