import { describe, it, expect, vi, beforeEach } from 'vitest'

vi.mock('node:fs/promises', () => ({
  mkdir: vi.fn(),
  access: vi.fn(),
  unlink: vi.fn(),
  readFile: vi.fn(),
  readdir: vi.fn(),
  writeFile: vi.fn(),
}))

import * as fs from 'node:fs/promises'
import { FileBackend } from '../../../src/backend/file-backend.js'
import { SecretNotFoundError } from '../../../src/errors.js'

const mockFs = vi.mocked(fs)

describe('FileBackend', () => {
  let backend: FileBackend

  beforeEach(() => {
    backend = new FileBackend()
    vi.clearAllMocks()
  })

  describe('isAvailable', () => {
    it('should return true when the storage directory can be created', async () => {
      mockFs.mkdir.mockResolvedValue(undefined)

      const result = await backend.isAvailable()
      expect(result).toBe(true)
    })

    it('should return false when storage directory creation fails with a filesystem error', async () => {
      const permError = Object.assign(new Error('Permission denied'), { code: 'EACCES' })
      mockFs.mkdir.mockRejectedValue(permError)

      const result = await backend.isAvailable()
      expect(result).toBe(false)
    })
  })

  describe('store', () => {
    it('should create storage directory and write the encrypted file', async () => {
      mockFs.mkdir.mockResolvedValue(undefined)
      // getOrCreateKey: readFile for key → ENOENT → writeFile for key
      const keyBytes = Buffer.alloc(32, 0xab)
      const noFileError = Object.assign(new Error('ENOENT'), { code: 'ENOENT' })
      mockFs.readFile.mockRejectedValueOnce(noFileError) // key not found
      mockFs.writeFile.mockResolvedValueOnce(undefined) // write key
      mockFs.writeFile.mockResolvedValueOnce(undefined) // write encrypted file

      await backend.store('my-secret', 'secret-value')

      expect(mockFs.mkdir).toHaveBeenCalledWith(
        expect.stringContaining('.vaultkeeper'),
        expect.objectContaining({ recursive: true }),
      )
      expect(mockFs.writeFile).toHaveBeenCalledTimes(2)
      // Second writeFile call is the encrypted entry
      const encryptedWriteCall = mockFs.writeFile.mock.calls[1]
      expect(encryptedWriteCall?.[0]).toEqual(expect.stringContaining('.enc'))
      // Stored value is a base64:base64:base64 string (iv:authTag:ciphertext)
      expect(encryptedWriteCall?.[1]).toEqual(expect.stringMatching(/^[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]*$/))
      void keyBytes
    })

    it('should reuse an existing key file', async () => {
      mockFs.mkdir.mockResolvedValue(undefined)
      // Return a valid 32-byte key buffer when key file exists
      const keyBuffer = Buffer.alloc(32, 0xcd)
      mockFs.readFile.mockResolvedValueOnce(keyBuffer) // key exists
      mockFs.writeFile.mockResolvedValueOnce(undefined) // write encrypted file

      await backend.store('my-secret', 'secret-value')

      expect(mockFs.writeFile).toHaveBeenCalledTimes(1)
    })
  })

  describe('retrieve', () => {
    it('should decrypt and return the secret', async () => {
      // Use a real AES-256-GCM round-trip through the module by providing
      // a properly-formatted encrypted string and the matching key.
      // We mock fs at a low level to inject real encrypted data.
      const crypto = await import('node:crypto')
      const key = crypto.randomBytes(32)
      const iv = crypto.randomBytes(12)
      const cipher = crypto.createCipheriv('aes-256-gcm', key, iv, { authTagLength: 16 })
      const encrypted = Buffer.concat([cipher.update('my-secret-value', 'utf8'), cipher.final()])
      const authTag = cipher.getAuthTag()
      const encoded = [
        iv.toString('base64'),
        authTag.toString('base64'),
        encrypted.toString('base64'),
      ].join(':')

      mockFs.mkdir.mockResolvedValue(undefined)
      // readFile for entry (called first in retrieve)
      mockFs.readFile.mockResolvedValueOnce(encoded) // entry file
      mockFs.readFile.mockResolvedValueOnce(key) // key file

      const result = await backend.retrieve('my-secret')
      expect(result).toBe('my-secret-value')
    })

    it('should throw SecretNotFoundError when file does not exist', async () => {
      const noFileError = Object.assign(new Error('ENOENT'), { code: 'ENOENT' })
      mockFs.readFile.mockRejectedValueOnce(noFileError)

      await expect(backend.retrieve('missing')).rejects.toBeInstanceOf(SecretNotFoundError)
    })

    it('should throw Error when decryption fails (bad auth tag)', async () => {
      // Provide a malformed encoded string that will fail decryption
      mockFs.mkdir.mockResolvedValue(undefined)
      const badEncoded = 'AAAA:BBBB:CCCC' // wrong base64 format for GCM
      const keyBuffer = Buffer.alloc(32, 0x01)
      mockFs.readFile.mockResolvedValueOnce(badEncoded)
      mockFs.readFile.mockResolvedValueOnce(keyBuffer)

      await expect(backend.retrieve('corrupted')).rejects.toThrow('Failed to decrypt secret')
    })
  })

  describe('delete', () => {
    it('should unlink the encrypted file', async () => {
      mockFs.unlink.mockResolvedValue(undefined)

      await backend.delete('my-secret')

      expect(mockFs.unlink).toHaveBeenCalledWith(expect.stringContaining('.enc'))
    })

    it('should throw SecretNotFoundError when file does not exist', async () => {
      const noFileError = Object.assign(new Error('ENOENT'), { code: 'ENOENT' })
      mockFs.unlink.mockRejectedValue(noFileError)

      await expect(backend.delete('missing')).rejects.toBeInstanceOf(SecretNotFoundError)
    })

    it('should rethrow non-ENOENT filesystem errors', async () => {
      const permError = Object.assign(new Error('EPERM'), { code: 'EPERM' })
      mockFs.unlink.mockRejectedValue(permError)

      await expect(backend.delete('protected')).rejects.toThrow('EPERM')
    })
  })

  describe('exists', () => {
    it('should return true when encrypted file exists', async () => {
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

  describe('list', () => {
    it('should return decoded secret IDs from .enc filenames', async () => {
      const id1Hex = Buffer.from('secret-1', 'utf8').toString('hex')
      const id2Hex = Buffer.from('secret-2', 'utf8').toString('hex')
      mockFs.readdir.mockResolvedValue([
        `${id1Hex}.enc`,
        `${id2Hex}.enc`,
        '.key', // should be filtered out
      ])

      const result = await backend.list()
      expect(result).toEqual(['secret-1', 'secret-2'])
    })

    it('should return an empty array when storage directory does not exist', async () => {
      mockFs.readdir.mockRejectedValue(new Error('ENOENT'))

      const result = await backend.list()
      expect(result).toEqual([])
    })

    it('should return an empty array when no .enc files exist', async () => {
      mockFs.readdir.mockResolvedValue(['.key'])

      const result = await backend.list()
      expect(result).toEqual([])
    })
  })
})
