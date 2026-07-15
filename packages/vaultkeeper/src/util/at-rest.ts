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
import { toFilesystemError, DecryptionError } from '../errors.js'

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
 * @internal
 */
export async function getOrCreateWrapKey(keyPath: string): Promise<Buffer> {
  let existing: Buffer | undefined
  try {
    existing = await fs.readFile(keyPath)
  } catch (err) {
    if (!(err instanceof Error && 'code' in err && err.code === 'ENOENT')) {
      throw toFilesystemError(err, 'wrapping key file', keyPath, 'read')
    }
  }

  if (existing?.byteLength === GCM_KEY_BYTES) {
    return existing
  }

  // Missing or corrupt (wrong length): (re)generate a fresh key in place.
  const key = crypto.randomBytes(GCM_KEY_BYTES)
  try {
    await fs.writeFile(keyPath, key, { mode: 0o600 })
  } catch (err) {
    throw toFilesystemError(err, 'wrapping key file', keyPath, 'write')
  }
  return key
}
