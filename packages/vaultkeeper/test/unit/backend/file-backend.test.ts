import { describe, it, expect, vi, beforeEach } from 'vitest'
import * as path from 'node:path'
import * as os from 'node:os'

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
import { getDefaultConfigDir } from '../../../src/config.js'
import { SecretNotFoundError, FilesystemError, DecryptionError } from '../../../src/errors.js'

const mockFs = vi.mocked(fs)

/** The new (issue #99) default storage dir: `<configDir>/file`. */
const defaultStorageDir = path.join(getDefaultConfigDir(), 'file')

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

      // Issue #99: default storage lives under the resolved config dir
      // (getDefaultConfigDir()/file), not the legacy $HOME/.vaultkeeper/file.
      expect(mockFs.mkdir).toHaveBeenCalledWith(
        defaultStorageDir,
        expect.objectContaining({ recursive: true }),
      )
      expect(mockFs.writeFile).toHaveBeenCalledTimes(2)
      // Second writeFile call is the encrypted entry
      const encryptedWriteCall = mockFs.writeFile.mock.calls[1]
      expect(encryptedWriteCall?.[0]).toEqual(expect.stringContaining('.enc'))
      // Stored value is a base64:base64:base64 string (iv:authTag:ciphertext)
      expect(encryptedWriteCall?.[1]).toEqual(
        expect.stringMatching(/^[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]*$/),
      )
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

    // Regression: issue #60 — BackendConfig.path was silently ignored.
    it('should store under a custom path from config, not the default location', async () => {
      const customDir = path.join(path.sep, 'custom', 'file', 'dir')
      const customBackend = new FileBackend(customDir)
      mockFs.mkdir.mockResolvedValue(undefined)
      const keyBuffer = Buffer.alloc(32, 0xcd)
      mockFs.readFile.mockResolvedValueOnce(keyBuffer) // key exists
      mockFs.writeFile.mockResolvedValueOnce(undefined) // write encrypted file

      await customBackend.store('my-secret', 'secret-value')

      expect(mockFs.mkdir).toHaveBeenCalledWith(
        customDir,
        expect.objectContaining({ recursive: true }),
      )
      const encryptedWriteCall = mockFs.writeFile.mock.calls[0]
      expect(encryptedWriteCall?.[0]).toEqual(expect.stringContaining(customDir))
      // Default config-dir-relative location must never be touched.
      expect(mockFs.mkdir).not.toHaveBeenCalledWith(defaultStorageDir, expect.anything())
    })

    // Regression: issue #115 — a permission failure writing the encrypted
    // entry previously propagated as the raw Node EACCES error instead of a
    // typed VaultError subclass.
    it('should surface an EACCES write failure as a typed FilesystemError', async () => {
      mockFs.mkdir.mockResolvedValueOnce(undefined)
      const keyBuffer = Buffer.alloc(32, 0xcd)
      mockFs.readFile.mockResolvedValueOnce(keyBuffer) // key exists
      const permError = Object.assign(new Error('permission denied'), { code: 'EACCES' })
      mockFs.writeFile.mockRejectedValueOnce(permError)

      let caught: unknown
      try {
        await backend.store('my-secret', 'secret-value')
      } catch (err) {
        caught = err
      }

      expect(caught).toBeInstanceOf(FilesystemError)
      if (caught instanceof FilesystemError) {
        expect(caught.message).toContain('permission denied')
      }
    })

    // Regression: issue #133 — the wrap that converts a caught fs failure
    // into a typed FilesystemError discarded the original
    // NodeJS.ErrnoException, so `.code` survived only as text embedded in
    // `.message` and `.cause` was never set. Consumers had no machine-readable
    // way to distinguish e.g. EACCES from ENOSPC.
    it('should preserve the errno code and cause on an EACCES write failure', async () => {
      mockFs.mkdir.mockResolvedValueOnce(undefined)
      const keyBuffer = Buffer.alloc(32, 0xcd)
      mockFs.readFile.mockResolvedValueOnce(keyBuffer) // key exists
      const permError = Object.assign(new Error('permission denied'), { code: 'EACCES' })
      mockFs.writeFile.mockRejectedValueOnce(permError)

      let caught: unknown
      try {
        await backend.store('my-secret', 'secret-value')
      } catch (err) {
        caught = err
      }

      expect(caught).toBeInstanceOf(FilesystemError)
      if (caught instanceof FilesystemError) {
        expect(caught.code).toBe('EACCES')
        expect(caught.cause).toBe(permError)
      }
    })

    // Regression: issue #133 — same errno-preservation guarantee for a
    // non-permission errno (disk full), which the message-text-only approach
    // couldn't reliably distinguish from a permission failure.
    it('should preserve the ENOSPC errno code and cause on a write failure (non-permission errno)', async () => {
      mockFs.mkdir.mockResolvedValueOnce(undefined)
      const keyBuffer = Buffer.alloc(32, 0xcd)
      mockFs.readFile.mockResolvedValueOnce(keyBuffer) // key exists
      const noSpaceError = Object.assign(new Error('no space left on device'), { code: 'ENOSPC' })
      mockFs.writeFile.mockRejectedValueOnce(noSpaceError)

      let caught: unknown
      try {
        await backend.store('my-secret', 'secret-value')
      } catch (err) {
        caught = err
      }

      expect(caught).toBeInstanceOf(FilesystemError)
      if (caught instanceof FilesystemError) {
        expect(caught.code).toBe('ENOSPC')
        expect(caught.cause).toBe(noSpaceError)
      }
    })

    // Regression: PR #126 review — getOrCreateWrapKey() (util/at-rest.ts),
    // used to read/create the `.key` wrapping-key file, still rethrew a raw
    // Node error on a non-ENOENT readFile failure, so an EACCES on the key
    // file (as opposed to the entry file) bypassed the typed-error wrapping
    // added for the entry read/write/delete paths.
    it('should surface an EACCES failure reading the wrapping key file as a typed FilesystemError', async () => {
      mockFs.mkdir.mockResolvedValueOnce(undefined)
      const permError = Object.assign(new Error('permission denied'), { code: 'EACCES' })
      mockFs.readFile.mockRejectedValueOnce(permError) // key file read fails

      let caught: unknown
      try {
        await backend.store('my-secret', 'secret-value')
      } catch (err) {
        caught = err
      }

      expect(caught).toBeInstanceOf(FilesystemError)
      if (caught instanceof FilesystemError) {
        expect(caught.message).toContain('permission denied')
        // Regression: issue #133 — the wrapping-key helper must also
        // preserve the errno code and cause, not just the message.
        expect(caught.code).toBe('EACCES')
        expect(caught.cause).toBe(permError)
      }
    })
  })

  describe('legacy $HOME/.vaultkeeper/file fallback (issue #99 back-compat)', () => {
    let legacyBackend: FileBackend
    const legacyStorageDir = path.join(os.homedir(), '.vaultkeeper', 'file')

    beforeEach(() => {
      // No explicit storageDir/configDir → legacy fallback is active.
      legacyBackend = new FileBackend()
      vi.clearAllMocks()
    })

    it('retrieve falls back to the legacy location when absent from the new default', async () => {
      const crypto = await import('node:crypto')
      const key = crypto.randomBytes(32)
      const iv = crypto.randomBytes(12)
      const cipher = crypto.createCipheriv('aes-256-gcm', key, iv, { authTagLength: 16 })
      const encrypted = Buffer.concat([cipher.update('legacy-value', 'utf8'), cipher.final()])
      const authTag = cipher.getAuthTag()
      const encoded = [
        iv.toString('base64'),
        authTag.toString('base64'),
        encrypted.toString('base64'),
      ].join(':')

      const noFileError = Object.assign(new Error('ENOENT'), { code: 'ENOENT' })
      mockFs.readFile.mockImplementation((target) => {
        const filePath = typeof target === 'string' ? target : ''
        if (filePath.startsWith(defaultStorageDir)) {
          return Promise.reject(noFileError)
        }
        if (filePath.endsWith('.enc')) {
          return Promise.resolve(encoded)
        }
        return Promise.resolve(key)
      })

      const result = await legacyBackend.retrieve('legacy-secret')
      expect(result).toBe('legacy-value')
      expect(mockFs.readFile).toHaveBeenCalledWith(
        expect.stringContaining(legacyStorageDir),
        'utf8',
      )
    })

    it('retrieve throws SecretNotFoundError when the secret exists in neither location', async () => {
      const noFileError = Object.assign(new Error('ENOENT'), { code: 'ENOENT' })
      mockFs.readFile.mockRejectedValue(noFileError)

      await expect(legacyBackend.retrieve('missing')).rejects.toBeInstanceOf(SecretNotFoundError)
    })

    it('does not consult the legacy location when an explicit path is configured', async () => {
      const explicitBackend = new FileBackend(path.join(path.sep, 'explicit', 'dir'))
      const noFileError = Object.assign(new Error('ENOENT'), { code: 'ENOENT' })
      mockFs.readFile.mockRejectedValue(noFileError)

      await expect(explicitBackend.retrieve('missing')).rejects.toBeInstanceOf(SecretNotFoundError)
      // Only the explicit dir was consulted — never the legacy dir.
      for (const call of mockFs.readFile.mock.calls) {
        const target = call[0]
        const filePath = typeof target === 'string' ? target : ''
        expect(filePath).not.toContain(legacyStorageDir)
      }
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

    it('should throw a typed DecryptionError when decryption fails (bad auth tag)', async () => {
      // Provide a malformed encoded string that will fail decryption
      mockFs.mkdir.mockResolvedValue(undefined)
      const badEncoded = 'AAAA:BBBB:CCCC' // wrong base64 format for GCM
      const keyBuffer = Buffer.alloc(32, 0x01)
      mockFs.readFile.mockResolvedValueOnce(badEncoded)
      mockFs.readFile.mockResolvedValueOnce(keyBuffer)

      await expect(backend.retrieve('corrupted')).rejects.toBeInstanceOf(DecryptionError)
      mockFs.readFile.mockResolvedValueOnce(badEncoded)
      mockFs.readFile.mockResolvedValueOnce(keyBuffer)
      await expect(backend.retrieve('corrupted')).rejects.toThrow('Failed to decrypt secret')
    })

    // Regression: issue #115 — a non-ENOENT read error (e.g. EACCES) reading
    // the encrypted entry previously propagated as the raw Node error instead
    // of a typed VaultError subclass.
    it('should surface an EACCES read failure as a typed FilesystemError', async () => {
      mockFs.mkdir.mockResolvedValueOnce(undefined)
      const permError = Object.assign(new Error('permission denied'), { code: 'EACCES' })
      mockFs.readFile.mockRejectedValueOnce(permError)

      let caught: unknown
      try {
        await backend.retrieve('protected')
      } catch (err) {
        caught = err
      }

      expect(caught).toBeInstanceOf(FilesystemError)
      if (caught instanceof FilesystemError) {
        expect(caught.message).toContain('permission denied')
        // Regression: issue #133 — errno code and cause must survive the
        // wrap, not just the message text.
        expect(caught.code).toBe('EACCES')
        expect(caught.cause).toBe(permError)
      }
    })

    // Regression: PR #126 review — an EACCES reading the `.key` wrapping-key
    // file (as opposed to the entry file) went through
    // getOrCreateWrapKey() (util/at-rest.ts), which still rethrew the raw
    // Node error rather than a typed FilesystemError.
    it('should surface an EACCES failure reading the wrapping key file as a typed FilesystemError', async () => {
      mockFs.mkdir.mockResolvedValueOnce(undefined)
      const permError = Object.assign(new Error('permission denied'), { code: 'EACCES' })
      // First readFile call (entry) succeeds; second (key file) fails.
      mockFs.readFile.mockResolvedValueOnce('AAAA:BBBB:CCCC')
      mockFs.readFile.mockRejectedValueOnce(permError)

      let caught: unknown
      try {
        await backend.retrieve('protected')
      } catch (err) {
        caught = err
      }

      expect(caught).toBeInstanceOf(FilesystemError)
      if (caught instanceof FilesystemError) {
        expect(caught.message).toContain('permission denied')
        expect(caught.code).toBe('EACCES')
        expect(caught.cause).toBe(permError)
      }
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

    // Regression: issue #115 — a non-ENOENT unlink error (e.g. EPERM/EACCES)
    // previously propagated as the raw Node error instead of a typed
    // VaultError subclass.
    it('should rethrow non-ENOENT filesystem errors as a typed FilesystemError', async () => {
      const permError = Object.assign(new Error('EPERM'), { code: 'EPERM' })
      mockFs.unlink.mockRejectedValueOnce(permError)

      let caught: unknown
      try {
        await backend.delete('protected')
      } catch (err) {
        caught = err
      }

      expect(caught).toBeInstanceOf(FilesystemError)
      if (caught instanceof FilesystemError) {
        expect(caught.message).toContain('EPERM')
        // Regression: issue #133 — the delete-path wrap must also preserve
        // the errno code and cause, not just embed the code in the message.
        expect(caught.code).toBe('EPERM')
        expect(caught.cause).toBe(permError)
      }
    })

    // Regression: PR #126 review — the delete path wrapped unlink failures
    // with the 'write' operation label, so the message read "Failed to
    // write secret file..." for what was actually a delete. Must say delete.
    it('should describe a non-ENOENT unlink failure as a delete, not a write', async () => {
      const permError = Object.assign(new Error('EPERM'), { code: 'EPERM' })
      mockFs.unlink.mockRejectedValueOnce(permError)

      let caught: unknown
      try {
        await backend.delete('protected')
      } catch (err) {
        caught = err
      }

      expect(caught).toBeInstanceOf(FilesystemError)
      if (caught instanceof FilesystemError) {
        expect(caught.permission).toBe('delete')
        expect(caught.message).toContain('Failed to delete secret file')
        expect(caught.message).not.toContain('Failed to write secret file')
      }
    })

    // Same operation-label bug on the legacy-location delete path.
    it('should describe a non-ENOENT unlink failure on the legacy path as a delete', async () => {
      const legacyBackendForDelete = new FileBackend()
      const noFileError = Object.assign(new Error('ENOENT'), { code: 'ENOENT' })
      const permError = Object.assign(new Error('EPERM'), { code: 'EPERM' })
      // Two unlink attempts in order: the primary path misses (ENOENT) so the
      // delete falls through to the legacy path, which then fails with EPERM.
      // Scope each rejection with *Once so neither leaks into later tests.
      mockFs.unlink.mockRejectedValueOnce(noFileError).mockRejectedValueOnce(permError)

      let caught: unknown
      try {
        await legacyBackendForDelete.delete('protected')
      } catch (err) {
        caught = err
      }

      expect(caught).toBeInstanceOf(FilesystemError)
      if (caught instanceof FilesystemError) {
        expect(caught.permission).toBe('delete')
        expect(caught.message).toContain('Failed to delete secret file')
      }
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
