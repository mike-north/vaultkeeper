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
import * as crypto from 'node:crypto'
import {
  SecretNotFoundError,
  FilesystemError,
  DecryptionError,
  toFilesystemError,
  SigningKeyNotFoundError,
  SigningKeyAlreadyExistsError,
  InvalidAlgorithmError,
  InvalidKeyMaterialError,
} from '../errors.js'
import { encryptGcm, decryptGcm, getOrCreateWrapKey } from '../util/at-rest.js'
import { getDefaultConfigDir } from '../config.js'
import type { ListableBackend, SigningBackend } from './types.js'
import type { SigningAlgorithm, SigningPublicKey } from '../types.js'

const STORAGE_DIR_NAME = 'file'
const KEY_FILE = '.key'
/**
 * Subdirectory (under the secret storage dir) holding encrypted signing-key
 * private material. Kept separate from the `.enc` secret files so a signing key
 * can never be read through {@link FileBackend.retrieve} or surface in
 * {@link FileBackend.list}.
 */
const SIGNING_DIR_NAME = 'signing-keys'
/** Namespace prefix for signing-key identifiers (see {@link SigningBackend}). */
const SIGNING_KEY_PREFIX = 'signing-key:'
/** Signing algorithms this backend can generate keys for. */
const SUPPORTED_SIGNING_ALGORITHMS: readonly SigningAlgorithm[] = ['EdDSA']

/** Compute the stable kid for an SPKI-DER public key: base64url(sha256(der)). */
function computeKid(spkiDer: Buffer): string {
  return crypto.createHash('sha256').update(spkiDer).digest('base64url')
}

/** Strip the namespace prefix to recover the caller-facing signing-key name. */
function displayKeyName(id: string): string {
  return id.startsWith(SIGNING_KEY_PREFIX) ? id.slice(SIGNING_KEY_PREFIX.length) : id
}

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
export class FileBackend implements ListableBackend, SigningBackend {
  readonly type = 'file'
  readonly displayName = 'Encrypted File Store'

  readonly #storageDir: string
  /** Directory holding encrypted signing-key private material. */
  readonly #signingDir: string
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
    this.#signingDir = path.join(this.#storageDir, SIGNING_DIR_NAME)
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

  // --- Signing contract (SigningBackend) ---

  /** On-disk path of the encrypted private key for a signing-key id. */
  #signingKeyPath(id: string): string {
    const safeId = Buffer.from(id, 'utf8').toString('hex')
    return path.join(this.#signingDir, `${safeId}.pem.enc`)
  }

  /**
   * Load and decrypt the PKCS#8 private key PEM for `id`, or throw
   * {@link SigningKeyNotFoundError} when no signing key exists under `id`.
   */
  async #loadSigningKeyPem(id: string): Promise<string> {
    const keyPath = this.#signingKeyPath(id)
    let encoded: string
    try {
      encoded = await fs.readFile(keyPath, 'utf8')
    } catch (err) {
      if (err instanceof Error && 'code' in err && err.code === 'ENOENT') {
        throw new SigningKeyNotFoundError(
          `Signing key not found: ${displayKeyName(id)}`,
          displayKeyName(id),
        )
      }
      throw toFilesystemError(err, 'signing key', keyPath, 'read')
    }
    const wrapKey = await getOrCreateKey(this.#storageDir)
    try {
      return decryptGcm(wrapKey, encoded)
    } catch (err) {
      throw new DecryptionError(
        `Failed to decrypt signing key: ${err instanceof Error ? err.message : String(err)}`,
        keyPath,
      )
    }
  }

  async generateSigningKey(id: string, algorithm: SigningAlgorithm): Promise<void> {
    // Runtime guard for JS callers that may bypass the compile-time type.
    if (!SUPPORTED_SIGNING_ALGORITHMS.includes(algorithm)) {
      throw new InvalidAlgorithmError(
        `Unsupported signing algorithm '${algorithm}'. Supported: ${SUPPORTED_SIGNING_ALGORITHMS.join(', ')}.`,
        algorithm,
        [...SUPPORTED_SIGNING_ALGORITHMS],
      )
    }
    await ensureStorageDir(this.#storageDir)
    try {
      await fs.mkdir(this.#signingDir, { recursive: true, mode: 0o700 })
    } catch (err) {
      if (err instanceof Error && 'code' in err && err.code !== 'EEXIST') {
        throw toFilesystemError(err, 'signing-key directory', this.#signingDir, 'create')
      }
    }

    const keyPath = this.#signingKeyPath(id)
    // Never silently replace an existing signing key — a regenerated key would
    // invalidate every previously exported/pinned public key (a signature-trust
    // break). Probe for an existing key, but distinguish the three outcomes:
    //   - access() succeeds        -> a key exists; refuse (already-exists).
    //   - access() fails w/ ENOENT -> confirmed absent; safe to generate.
    //   - access() fails otherwise -> a transient/permission fault (e.g. EACCES).
    //     Treating that as "absent" could clobber an existing key, so surface it
    //     as a typed FilesystemError instead of proceeding.
    let keyExists = false
    try {
      await fs.access(keyPath)
      keyExists = true
    } catch (err) {
      if (!(err instanceof Error && 'code' in err && err.code === 'ENOENT')) {
        throw toFilesystemError(err, 'signing key', keyPath, 'read')
      }
      // ENOENT: confirmed absent — fall through to generation.
    }
    if (keyExists) {
      throw new SigningKeyAlreadyExistsError(
        `Signing key already exists: ${displayKeyName(id)}`,
        displayKeyName(id),
      )
    }

    const { privateKey } = crypto.generateKeyPairSync('ed25519')
    const pkcs8Pem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString()
    const wrapKey = await getOrCreateKey(this.#storageDir)
    const encrypted = encryptGcm(wrapKey, pkcs8Pem)
    try {
      // wx: fail if the path was created between our probe and here (TOCTOU),
      // so a concurrent enrollment can never be silently overwritten either.
      await fs.writeFile(keyPath, encrypted, { mode: 0o600, flag: 'wx' })
    } catch (err) {
      if (err instanceof Error && 'code' in err && err.code === 'EEXIST') {
        throw new SigningKeyAlreadyExistsError(
          `Signing key already exists: ${displayKeyName(id)}`,
          displayKeyName(id),
        )
      }
      throw toFilesystemError(err, 'signing key', keyPath, 'write')
    }
  }

  /**
   * Load, decrypt, and parse the private key for `id` into a `KeyObject`.
   *
   * A parse failure means the decrypted-at-rest material is corrupt or tampered
   * (it decrypted cleanly but is not a valid PKCS#8 private key). It is
   * translated into a typed {@link InvalidKeyMaterialError} — never allowed to
   * surface as a raw Node crypto exception — and the message never echoes any
   * part of the key material.
   */
  async #loadSigningKeyObject(id: string): Promise<crypto.KeyObject> {
    const pkcs8Pem = await this.#loadSigningKeyPem(id)
    try {
      return crypto.createPrivateKey(pkcs8Pem)
    } catch {
      throw new InvalidKeyMaterialError(
        `The stored signing key for "${displayKeyName(id)}" is not valid private key material ` +
          '(it may be corrupt or tampered).',
      )
    }
  }

  async getPublicKey(id: string): Promise<SigningPublicKey> {
    const privateKey = await this.#loadSigningKeyObject(id)
    const publicKey = crypto.createPublicKey(privateKey)
    const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }).toString()
    const spkiDer = publicKey.export({ type: 'spki', format: 'der' })
    return {
      publicKeyPem,
      algorithm: 'EdDSA',
      kid: computeKid(spkiDer),
    }
  }

  async signWithKey(id: string, data: Buffer): Promise<Buffer> {
    const privateKey = await this.#loadSigningKeyObject(id)
    // Ed25519: the algorithm is implicit in the key, so pass null.
    return crypto.sign(null, data, privateKey)
  }
}
