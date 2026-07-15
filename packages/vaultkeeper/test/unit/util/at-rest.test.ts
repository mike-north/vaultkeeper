import { describe, it, expect } from 'vitest'
import * as crypto from 'node:crypto'
import { encryptGcm, decryptGcm } from '../../../src/util/at-rest.js'
import { DecryptionError } from '../../../src/errors.js'

const KEY = crypto.randomBytes(32)

describe('encryptGcm / decryptGcm', () => {
  it('round-trips plaintext through encrypt then decrypt', () => {
    const encrypted = encryptGcm(KEY, 'hunter2')
    expect(decryptGcm(KEY, encrypted, '/entries/a.enc')).toBe('hunter2')
  })

  // Regression: issue #127 — a malformed envelope (wrong number of
  // colon-separated parts) previously threw a plain `Error`, breaking
  // instanceof-based handling. It must now throw a typed DecryptionError
  // naming the entry's path.
  it('throws a typed DecryptionError naming the path for a malformed envelope', () => {
    try {
      decryptGcm(KEY, 'only:two', '/entries/corrupt.enc')
      expect.unreachable('decryptGcm should have thrown for a malformed envelope')
    } catch (err) {
      if (!(err instanceof DecryptionError)) {
        throw err
      }
      expect(err.path).toBe('/entries/corrupt.enc')
      expect(err.message).toContain('iv:authTag:ciphertext')
    }
  })

  it('defaults path to an empty string when the caller has none to give', () => {
    try {
      decryptGcm(KEY, 'only:two')
      expect.unreachable('decryptGcm should have thrown for a malformed envelope')
    } catch (err) {
      if (!(err instanceof DecryptionError)) {
        throw err
      }
      expect(err.path).toBe('')
    }
  })

  it('throws a typed DecryptionError for a tampered auth tag', () => {
    const encrypted = encryptGcm(KEY, 'hunter2')
    const parts = encrypted.split(':')
    const ciphertext = parts[2] ?? ''
    // Flip a byte in the ciphertext so GCM authentication fails.
    const bytes = Buffer.from(ciphertext, 'base64')
    bytes[0] = (bytes[0] ?? 0) ^ 0xff
    const tampered = [parts[0], parts[1], bytes.toString('base64')].join(':')

    expect(() => decryptGcm(KEY, tampered, '/entries/a.enc')).toThrow()
  })
})
