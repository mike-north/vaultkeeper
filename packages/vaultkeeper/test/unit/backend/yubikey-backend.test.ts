/**
 * Unit tests for YubikeyBackend.
 *
 * The YubiKey HMAC-SHA1 challenge-response and all filesystem I/O are mocked
 * so tests run without hardware. Crypto operations use the real Node.js `crypto`
 * module to validate AES-256-GCM correctness.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import * as crypto from 'node:crypto'
import type { ExecCommandResult } from '../../../src/util/exec.js'

vi.mock('../../../src/util/exec.js', () => ({
  execCommand: vi.fn(),
  execCommandFull: vi.fn(),
}))

vi.mock('node:fs/promises', () => ({
  mkdir: vi.fn(),
  access: vi.fn(),
  unlink: vi.fn(),
  readFile: vi.fn(),
  writeFile: vi.fn(),
}))

import * as fs from 'node:fs/promises'
import { execCommandFull } from '../../../src/util/exec.js'
import { YubikeyBackend } from '../../../src/backend/yubikey-backend.js'
import {
  SecretNotFoundError,
  PluginNotFoundError,
  DeviceNotPresentError,
} from '../../../src/errors.js'

const mockExecCommandFull = vi.mocked(execCommandFull)
const mockFs = vi.mocked(fs)

function makeResult(exitCode: number, stdout = '', stderr = ''): ExecCommandResult {
  return { exitCode, stdout, stderr }
}

/**
 * Set up the standard ykman availability mocks:
 * - `ykman --version` → success
 * - `ykman list` → device present
 */
function mockDeviceAvailable(): void {
  mockExecCommandFull
    .mockResolvedValueOnce(makeResult(0, 'ykman 5.4.0'))
    .mockResolvedValueOnce(makeResult(0, 'YubiKey 5 NFC'))
}

/**
 * Set up ykman mock to return a challenge-response hex string.
 * The hex string must be a valid hex-encoded buffer for HKDF to work.
 */
function mockChallengeResponse(hexResponse: string): void {
  mockExecCommandFull.mockResolvedValueOnce(makeResult(0, hexResponse))
}

/**
 * A stable 40-hex-char fake HMAC-SHA1 response for test reproducibility.
 * (20 bytes = 40 hex chars, matching real ykman output.)
 */
const FAKE_HMAC_RESPONSE = 'deadbeefcafe01234567deadbeefcafe01234567'

/**
 * Produce a valid GCM-encrypted blob for `plaintext` using the same key
 * derivation the backend uses, so retrieve tests can feed a realistic file.
 */
function makeEncryptedBlob(plaintext: string, id: string): string {
  // Replicate the backend's key derivation inline.
  const ikm = Buffer.from(FAKE_HMAC_RESPONSE, 'hex')
  const info = Buffer.from(`vaultkeeper-yubikey:${id}`, 'utf8')
  const keyMaterial = crypto.hkdfSync('sha256', ikm, Buffer.alloc(0), info, 32)
  const key = Buffer.from(keyMaterial)

  const iv = crypto.randomBytes(12)
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv, { authTagLength: 16 })
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()])
  const authTag = cipher.getAuthTag()

  return ['1', iv.toString('base64'), authTag.toString('base64'), encrypted.toString('base64')].join(
    ':',
  )
}

describe('YubikeyBackend', () => {
  let backend: YubikeyBackend

  beforeEach(() => {
    backend = new YubikeyBackend()
    vi.clearAllMocks()
  })

  // ---------------------------------------------------------------------------
  // isAvailable
  // ---------------------------------------------------------------------------

  describe('isAvailable', () => {
    it('should return true when ykman is installed and device is connected', async () => {
      mockExecCommandFull
        .mockResolvedValueOnce(makeResult(0, 'YubiKey Manager (ykman) version: 5.4.0'))
        .mockResolvedValueOnce(makeResult(0, 'YubiKey 5 NFC (5.4.3) [OTP+FIDO+CCID] Serial: 12345'))

      const result = await backend.isAvailable()
      expect(result).toBe(true)
    })

    it('should return false when ykman is not installed', async () => {
      mockExecCommandFull.mockRejectedValue(new Error('command not found: ykman'))

      const result = await backend.isAvailable()
      expect(result).toBe(false)
    })

    it('should return false when no device is connected', async () => {
      mockExecCommandFull
        .mockResolvedValueOnce(makeResult(0, 'ykman 5.4.0'))
        .mockResolvedValueOnce(makeResult(0, '')) // empty list

      const result = await backend.isAvailable()
      expect(result).toBe(false)
    })
  })

  // ---------------------------------------------------------------------------
  // store
  // ---------------------------------------------------------------------------

  describe('store', () => {
    it('should perform challenge-response and write a GCM-encrypted file', async () => {
      mockDeviceAvailable()
      mockChallengeResponse(FAKE_HMAC_RESPONSE)

      mockFs.mkdir.mockResolvedValue(undefined)
      // metadata load: file does not exist yet
      mockFs.readFile.mockRejectedValue(Object.assign(new Error('ENOENT'), { code: 'ENOENT' }))
      mockFs.writeFile.mockResolvedValue(undefined)

      await backend.store('my-secret', 'secret-value')

      // The challenge should include the secret id encoded as hex.
      expect(mockExecCommandFull).toHaveBeenCalledWith('ykman', [
        'otp',
        'calculate',
        '2',
        expect.any(String),
      ])

      // writeFile should have been called twice: once for the secret file,
      // once for the metadata file.
      expect(mockFs.writeFile).toHaveBeenCalledTimes(2)

      // Verify the encrypted payload written to the secret file is a valid
      // versioned GCM blob (1:<iv>:<authTag>:<ciphertext>).
      const secretFileCall = mockFs.writeFile.mock.calls.find(
        ([p]) => typeof p === 'string' && p.endsWith('.enc'),
      )
      expect(secretFileCall).toBeDefined()
      const writtenContent = secretFileCall?.[1]
      expect(typeof writtenContent).toBe('string')
      if (typeof writtenContent === 'string') {
        const parts = writtenContent.split(':')
        expect(parts[0]).toBe('1') // version prefix
        expect(parts).toHaveLength(4) // 1:iv:authTag:ciphertext
      }
    })

    it('should NOT invoke openssl — encryption is pure Node.js crypto', async () => {
      mockDeviceAvailable()
      mockChallengeResponse(FAKE_HMAC_RESPONSE)
      mockFs.mkdir.mockResolvedValue(undefined)
      mockFs.readFile.mockRejectedValue(Object.assign(new Error('ENOENT'), { code: 'ENOENT' }))
      mockFs.writeFile.mockResolvedValue(undefined)

      await backend.store('my-secret', 'secret-value')

      // execCommandFull should only have been called for ykman, never for openssl.
      const opensslCall = mockExecCommandFull.mock.calls.find(([cmd]) => cmd === 'openssl')
      expect(opensslCall).toBeUndefined()
    })

    it('should throw PluginNotFoundError when ykman is not installed', async () => {
      mockExecCommandFull.mockRejectedValue(new Error('command not found'))

      await expect(backend.store('my-secret', 'value')).rejects.toBeInstanceOf(PluginNotFoundError)
    })

    it('should throw DeviceNotPresentError when no device is connected', async () => {
      mockExecCommandFull
        .mockReset()
        .mockResolvedValueOnce(makeResult(0, 'ykman 5.4.0')) // isAvailable: ykman --version
        .mockResolvedValueOnce(makeResult(0, '')) // ykman list → empty → isAvailable false
        .mockResolvedValueOnce(makeResult(0, 'ykman 5.4.0')) // requireDevice: hasYkman check

      await expect(backend.store('my-secret', 'value')).rejects.toBeInstanceOf(
        DeviceNotPresentError,
      )
    })
  })

  // ---------------------------------------------------------------------------
  // retrieve
  // ---------------------------------------------------------------------------

  describe('retrieve', () => {
    it('should throw SecretNotFoundError when file does not exist', async () => {
      mockDeviceAvailable()

      mockFs.access.mockRejectedValue(Object.assign(new Error('ENOENT'), { code: 'ENOENT' }))

      await expect(backend.retrieve('missing')).rejects.toBeInstanceOf(SecretNotFoundError)
    })

    it('should decrypt and return the secret (roundtrip with real GCM)', async () => {
      const id = 'my-secret'
      const plaintext = 'hunter2'
      const blob = makeEncryptedBlob(plaintext, id)

      mockDeviceAvailable()
      mockChallengeResponse(FAKE_HMAC_RESPONSE)

      mockFs.access.mockResolvedValue(undefined)
      mockFs.readFile.mockResolvedValue(blob)

      const result = await backend.retrieve(id)
      expect(result).toBe(plaintext)
    })

    it('should reject a tampered ciphertext (auth tag validation)', async () => {
      const id = 'tampered-secret'
      const blob = makeEncryptedBlob('original', id)

      // Corrupt the ciphertext bytes by flipping a bit in the raw binary before
      // re-encoding. The blob format is 1:iv:authTag:ciphertext.
      const lastColon = blob.lastIndexOf(':')
      const ciphertextB64 = blob.slice(lastColon + 1)
      const ciphertextBytes = Buffer.from(ciphertextB64, 'base64')
      // XOR the first byte to ensure the ciphertext differs from what the auth
      // tag covers — GCM must reject this.
      ciphertextBytes[0] = (ciphertextBytes[0] ?? 0) ^ 0xff
      const corruptedBlob =
        blob.slice(0, lastColon + 1) + ciphertextBytes.toString('base64')

      mockDeviceAvailable()
      mockChallengeResponse(FAKE_HMAC_RESPONSE)
      mockFs.access.mockResolvedValue(undefined)
      mockFs.readFile.mockResolvedValue(corruptedBlob)

      await expect(backend.retrieve(id)).rejects.toThrow(/GCM authentication failed/)
    })

    it('should give a clear error for a legacy AES-256-CBC encrypted file', async () => {
      // A legacy file does not start with a numeric version prefix — simulate
      // binary openssl enc output (e.g. "Salted__...") or any non-versioned content.
      const legacyContent = 'Salted__somebinarycbcdata'

      mockDeviceAvailable()
      mockChallengeResponse(FAKE_HMAC_RESPONSE)
      mockFs.access.mockResolvedValue(undefined)
      mockFs.readFile.mockResolvedValue(legacyContent)

      await expect(backend.retrieve('legacy-secret')).rejects.toThrow(/legacy format.*AES-256-CBC/)
    })

    it('should give a clear "unsupported version" error for a future format version', async () => {
      // Regression: previously any non-current version was treated as "legacy
      // CBC". A file starting with a numeric version that is not FORMAT_VERSION
      // should instead produce an "unsupported version" error so users know to
      // upgrade vaultkeeper rather than being told to migrate from CBC.
      const futureVersionBlob = '42:aXY=:dGFn:Y2lwaGVydGV4dA=='

      mockDeviceAvailable()
      mockChallengeResponse(FAKE_HMAC_RESPONSE)
      mockFs.access.mockResolvedValue(undefined)
      mockFs.readFile.mockResolvedValue(futureVersionBlob)

      await expect(backend.retrieve('future-secret')).rejects.toThrow(
        /[Uu]nsupported.*version.*42/,
      )
    })

    it('should give a clear error for an invalid HMAC response (not 40 hex chars)', async () => {
      // Regression: a truncated or malformed ykman response should produce a
      // descriptive error from deriveKey rather than silently generating a bad key.
      const id = 'my-secret'
      const blob = makeEncryptedBlob('value', id)

      mockDeviceAvailable()
      // Return a response that is only 8 hex chars — far too short.
      mockChallengeResponse('deadbeef')
      mockFs.access.mockResolvedValue(undefined)
      mockFs.readFile.mockResolvedValue(blob)

      await expect(backend.retrieve(id)).rejects.toThrow(/Invalid YubiKey HMAC response/)
    })
  })

  // ---------------------------------------------------------------------------
  // delete
  // ---------------------------------------------------------------------------

  describe('delete', () => {
    it('should unlink the file when it exists', async () => {
      mockDeviceAvailable()

      mockFs.unlink.mockResolvedValue(undefined)
      mockFs.readFile.mockRejectedValue(Object.assign(new Error('ENOENT'), { code: 'ENOENT' }))
      mockFs.writeFile.mockResolvedValue(undefined)

      await backend.delete('my-secret')

      expect(mockFs.unlink).toHaveBeenCalledWith(expect.stringContaining('.enc'))
    })

    it('should throw SecretNotFoundError when file does not exist', async () => {
      mockDeviceAvailable()

      const noFileError = Object.assign(new Error('ENOENT'), { code: 'ENOENT' })
      mockFs.unlink.mockRejectedValue(noFileError)

      await expect(backend.delete('missing')).rejects.toBeInstanceOf(SecretNotFoundError)
    })
  })

  // ---------------------------------------------------------------------------
  // exists
  // ---------------------------------------------------------------------------

  describe('exists', () => {
    it('should return true when encrypted file exists (no device needed)', async () => {
      mockFs.access.mockResolvedValue(undefined)

      const result = await backend.exists('my-secret')
      expect(result).toBe(true)
    })

    it('should return false when encrypted file does not exist', async () => {
      mockFs.access.mockRejectedValue(new Error('ENOENT'))

      const result = await backend.exists('missing')
      expect(result).toBe(false)
    })
  })
})
