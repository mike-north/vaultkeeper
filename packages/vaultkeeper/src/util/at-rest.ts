/**
 * Shared AES-256-GCM helpers for encrypting data at rest under a locally
 * stored wrapping key.
 *
 * @remarks
 * These primitives back both the encrypted {@link FileBackend} secret store and
 * the persisted {@link KeyManager} key material. Keeping a single implementation
 * ensures every at-rest write in the codebase uses the same authenticated
 * cipher (AES-256-GCM, never AES-CBC) and the same on-disk envelope, rather than
 * re-deriving crypto per consumer.
 *
 * Envelope format (all parts base64, colon-separated):
 *   `<iv>:<authTag>:<ciphertext>`
 *
 * @internal
 */

import * as fs from 'node:fs/promises'
import * as crypto from 'node:crypto'
import * as path from 'node:path'
import { toFilesystemError, DecryptionError, FilesystemError } from '../errors.js'

const GCM_IV_BYTES = 12
const GCM_KEY_BYTES = 32
const GCM_TAG_LENGTH_BITS = 128

/**
 * Encrypt `plaintext` with AES-256-GCM under `key`, returning the
 * `iv:authTag:ciphertext` envelope described in the module docs.
 *
 * @param key - 32-byte AES-256 wrapping key.
 * @param plaintext - UTF-8 string to encrypt.
 * @internal
 */
export function encryptGcm(key: Buffer, plaintext: string): string {
  const iv = crypto.randomBytes(GCM_IV_BYTES)
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv, {
    authTagLength: GCM_TAG_LENGTH_BITS / 8,
  })
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()])
  const authTag = cipher.getAuthTag()
  return [iv.toString('base64'), authTag.toString('base64'), encrypted.toString('base64')].join(':')
}

/**
 * Decrypt an `iv:authTag:ciphertext` envelope produced by {@link encryptGcm}.
 *
 * @param key - The same 32-byte AES-256 wrapping key used to encrypt.
 * @param encoded - The colon-separated envelope.
 * @param path - The path of the encrypted entry being decrypted, for
 * attribution on a thrown {@link DecryptionError}. Callers that don't yet
 * have a path (e.g. an in-memory envelope) may omit it.
 * @returns The decrypted UTF-8 plaintext.
 * @throws {DecryptionError} If the envelope is malformed or authentication fails.
 * @internal
 */
export function decryptGcm(key: Buffer, encoded: string, path = ''): string {
  const parts = encoded.split(':')
  if (parts.length !== 3) {
    throw new DecryptionError('Invalid encrypted envelope: expected iv:authTag:ciphertext', path)
  }
  const [ivB64, authTagB64, ciphertextB64] = parts
  if (ivB64 === undefined || authTagB64 === undefined || ciphertextB64 === undefined) {
    throw new DecryptionError('Invalid encrypted envelope: missing part', path)
  }
  const iv = Buffer.from(ivB64, 'base64')
  const authTag = Buffer.from(authTagB64, 'base64')
  const ciphertext = Buffer.from(ciphertextB64, 'base64')

  try {
    // Inside the try from createDecipheriv onward: the iv and authTag lengths
    // come from the on-disk envelope, so a truncated/corrupt entry can make
    // createDecipheriv or setAuthTag throw a native RangeError/TypeError —
    // not just decipher.final()'s auth-tag failure.
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv, {
      authTagLength: GCM_TAG_LENGTH_BITS / 8,
    })
    decipher.setAuthTag(authTag)
    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()])
    return decrypted.toString('utf8')
  } catch (err) {
    // Wrap every native crypto failure so the documented
    // @throws {DecryptionError} contract holds on every path.
    throw new DecryptionError(
      `Failed to decrypt envelope: ${err instanceof Error ? err.message : String(err)}`,
      path,
    )
  }
}

/** Signing requires no-replace publication. Ordinary storage can also use sequential filesystems. */
type Publication = 'atomic' | 'sequential-fallback'

/** A rename consumes the stage. Other outcomes leave it to clean up. */
type StagedPublication = 'linked' | 'exists' | 'renamed'

/** Give the publisher exclusive ownership of a complete, owner-only sibling file. */
async function withPrivateStage(
  dest: string,
  content: string | Buffer,
  resource: string,
  publish: (temp: string) => Promise<StagedPublication>,
): Promise<StagedPublication> {
  // Match the 13-byte staging basename for keys.enc so wrapping-key
  // publication fits wherever the key state can be saved.
  const temp = path.join(path.dirname(dest), `.${crypto.randomBytes(9).toString('base64url')}`)
  let file: Awaited<ReturnType<typeof fs.open>>
  try {
    file = await fs.open(temp, 'wx', 0o600)
  } catch (err) {
    throw toFilesystemError(err, resource, dest, 'write')
  }

  let result: StagedPublication | undefined
  try {
    try {
      await file.writeFile(content)
      if (process.platform !== 'win32') await file.chmod(0o600)
    } catch (err) {
      await file.close().catch(() => undefined)
      throw err
    }
    await file.close()
    result = await publish(temp)
    return result
  } catch (err) {
    throw toFilesystemError(err, resource, dest, 'write')
  } finally {
    // A rename released the stage path, so it could now belong to another writer.
    if (result !== 'renamed') await fs.unlink(temp).catch(() => undefined)
  }
}

/**
 * Publish a complete private file without replacement. Ordinary wrapping keys
 * may opt into a sequential rename when the filesystem lacks hard links.
 * @internal
 */
export async function writeFileIfAbsent(
  dest: string,
  content: string | Buffer,
  resource: string,
  publication: Publication = 'atomic',
): Promise<boolean> {
  const result = await withPrivateStage(dest, content, resource, async (temp) => {
    try {
      await fs.link(temp, dest)
      return 'linked'
    } catch (err) {
      if (!(err instanceof Error && 'code' in err)) throw err
      if (err.code === 'EEXIST') return 'exists'
      // libuv can report the Windows exFAT link failure as EISDIR.
      const unavailable =
        err.code === 'ENOTSUP' ||
        err.code === 'EOPNOTSUPP' ||
        err.code === 'ENOSYS' ||
        err.code === 'EPERM' ||
        (process.platform === 'win32' && err.code === 'EISDIR')
      if (publication === 'atomic' || !unavailable) throw err
    }

    // An owned sibling can still be renamed when the filesystem refuses to
    // link it with EPERM. Signing requires the hard link's no-replace guarantee.
    try {
      await fs.lstat(dest)
      return 'exists'
    } catch (err) {
      if (!(err instanceof Error && 'code' in err && err.code === 'ENOENT')) throw err
    }
    await fs.rename(temp, dest)
    return 'renamed'
  })
  return result !== 'exists'
}

/**
 * Read the 32-byte wrapping key at `keyPath`, generating and persisting a fresh
 * random one (mode `0o600`) when the file does not yet exist **or** holds a
 * value that is not exactly 32 bytes.
 *
 * @remarks
 * Regenerating on a wrong-length key is safe, not data loss: a wrapping key of
 * the wrong length cannot decrypt anything it previously encrypted (the AES-256
 * cipher requires a 32-byte key), so any ciphertext under a corrupt key is
 * already unrecoverable. Without this guard, a truncated/corrupt key file would
 * make {@link encryptGcm} throw "Invalid key length" on every write, wedging the
 * consumer instead of degrading to a fresh key.
 *
 * The caller is responsible for ensuring the parent directory exists. The
 * returned {@link Buffer} holds key material; zero it after use where practical.
 *
 * @param keyPath - Absolute path to the wrapping-key file.
 * @param publication - Whether initial creation or repair requires atomic
 * no-replace publication. Signing must use the atomic mode.
 * @internal
 */
export async function getOrCreateWrapKey(
  keyPath: string,
  publication: Publication = 'sequential-fallback',
): Promise<Buffer> {
  let existing: Buffer | undefined
  try {
    existing = await fs.readFile(keyPath)
  } catch (err) {
    if (!(err instanceof Error && 'code' in err && err.code === 'ENOENT')) {
      throw toFilesystemError(err, 'wrapping key file', keyPath, 'read')
    }
  }

  if (existing?.byteLength === GCM_KEY_BYTES) return existing
  if (existing !== undefined) {
    existing.fill(0)
    return repairWrapKey(keyPath, publication)
  }

  const key = crypto.randomBytes(GCM_KEY_BYTES)
  let published = false
  try {
    published = await writeFileIfAbsent(keyPath, key, 'wrapping key file', publication)
    if (published) return key
  } finally {
    if (!published) key.fill(0)
  }

  return readValidWrapKey(keyPath)
}

async function readValidWrapKey(keyPath: string): Promise<Buffer> {
  let key: Buffer
  try {
    key = await fs.readFile(keyPath)
  } catch (err) {
    throw toFilesystemError(err, 'wrapping key file', keyPath, 'read')
  }
  if (key.byteLength === GCM_KEY_BYTES) return key
  key.fill(0)
  throw new DecryptionError('Invalid wrapping key length', keyPath)
}

/** Resume any published repair so every writer uses the same selected key. */
async function repairWrapKey(keyPath: string, publication: Publication): Promise<Buffer> {
  // Rust uses the same short suffix so both runtimes can finish each other's
  // repairs of a shared .keys.wrap, including in long config paths.
  const candidatePath = `${keyPath}.r`
  let candidate: Buffer = crypto.randomBytes(GCM_KEY_BYTES)
  let returnCandidate = false
  try {
    if (!(await writeFileIfAbsent(candidatePath, candidate, 'wrapping key repair', publication))) {
      candidate.fill(0)
      try {
        candidate = await readValidWrapKey(candidatePath)
      } catch (err) {
        // The selected candidate can disappear after a peer installs it.
        if (err instanceof FilesystemError && err.code === 'ENOENT') {
          return await readValidWrapKey(keyPath)
        }
        throw err
      }
    }

    let active: Buffer
    try {
      active = await readValidWrapKey(keyPath)
    } catch (err) {
      if (!(err instanceof DecryptionError)) throw err
      await installWrapKeyRepair(keyPath, candidate)
      active = candidate
    }
    // Only remove the shared candidate once a complete active key is available.
    await fs.unlink(candidatePath).catch(() => undefined)
    returnCandidate = active === candidate
    return active
  } finally {
    if (!returnCandidate) candidate.fill(0)
  }
}

/** Install a private copy of the selected key so a delayed writer cannot rename a reused candidate path. */
async function installWrapKeyRepair(keyPath: string, candidate: Buffer): Promise<void> {
  await withPrivateStage(keyPath, candidate, 'wrapping key repair', async (temp) => {
    await fs.rename(temp, keyPath)
    return 'renamed'
  })
}
