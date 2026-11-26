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

import { hasErrorCode, publishFile } from './publish-file.js'

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

/** Read an existing key without creating a replacement. */
export async function readWrapKey(keyPath: string): Promise<Buffer> {
  const key = await readKeyIfPresent(keyPath)
  if (key === undefined) throw new DecryptionError('Missing key material', keyPath)
  return key
}

async function readKeyIfPresent(keyPath: string): Promise<Buffer | undefined> {
  let key: Buffer
  try {
    key = await fs.readFile(keyPath)
  } catch (err) {
    if (hasErrorCode(err, 'ENOENT')) return undefined
    throw toFilesystemError(err, 'wrapping key file', keyPath, 'read')
  }
  if (key.byteLength === GCM_KEY_BYTES) return key
  key.fill(0)
  throw new DecryptionError('Invalid key material: expected 32 bytes', keyPath)
}

/** Create a key only when absent, or read the complete key published by another writer. */
export async function getOrCreateWrapKey(keyPath: string): Promise<Buffer> {
  const existing = await readKeyIfPresent(keyPath)
  if (existing !== undefined) return existing

  const candidate = crypto.randomBytes(GCM_KEY_BYTES)
  try {
    if (await publishFile(keyPath, candidate, 'wrapping key file')) return Buffer.from(candidate)
  } finally {
    candidate.fill(0)
  }
  return readWrapKey(keyPath)
}
