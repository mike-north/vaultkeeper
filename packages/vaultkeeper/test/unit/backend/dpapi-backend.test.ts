import { describe, it, expect, vi, beforeEach } from 'vitest'
import * as path from 'node:path'
import type { ExecCommandResult } from '../../../src/util/exec.js'

vi.mock('../../../src/util/exec.js', () => ({
  execCommand: vi.fn(),
  execCommandFull: vi.fn(),
}))

vi.mock('node:fs/promises', () => ({
  mkdir: vi.fn(),
  access: vi.fn(),
  unlink: vi.fn(),
  readdir: vi.fn(),
}))

import * as fs from 'node:fs/promises'
import { execCommand, execCommandFull } from '../../../src/util/exec.js'
import { DpapiBackend } from '../../../src/backend/dpapi-backend.js'
import { SecretNotFoundError, FilesystemError } from '../../../src/errors.js'

const mockExecCommand = vi.mocked(execCommand)
const mockExecCommandFull = vi.mocked(execCommandFull)
const mockFs = vi.mocked(fs)

function makeResult(exitCode: number, stdout = '', stderr = ''): ExecCommandResult {
  return { exitCode, stdout, stderr }
}

describe('DpapiBackend', () => {
  let backend: DpapiBackend

  beforeEach(() => {
    backend = new DpapiBackend()
    vi.clearAllMocks()
  })

  describe('isAvailable', () => {
    it('should return true on win32 when powershell succeeds', async () => {
      const originalPlatform = process.platform
      Object.defineProperty(process, 'platform', { value: 'win32', configurable: true })
      mockExecCommandFull.mockResolvedValue(makeResult(0))

      const result = await backend.isAvailable()
      expect(result).toBe(true)

      Object.defineProperty(process, 'platform', { value: originalPlatform, configurable: true })
    })

    it('should return false on non-windows platforms', async () => {
      const originalPlatform = process.platform
      Object.defineProperty(process, 'platform', { value: 'darwin', configurable: true })

      const result = await backend.isAvailable()
      expect(result).toBe(false)

      Object.defineProperty(process, 'platform', { value: originalPlatform, configurable: true })
    })

    it('should return false when powershell fails', async () => {
      const originalPlatform = process.platform
      Object.defineProperty(process, 'platform', { value: 'win32', configurable: true })
      mockExecCommandFull.mockRejectedValue(new Error('powershell not found'))

      const result = await backend.isAvailable()
      expect(result).toBe(false)

      Object.defineProperty(process, 'platform', { value: originalPlatform, configurable: true })
    })
  })

  describe('store', () => {
    it('should create storage directory and run powershell encrypt', async () => {
      mockFs.mkdir.mockResolvedValue(undefined)
      mockExecCommand.mockResolvedValue('')

      await backend.store('my-secret', 'secret-value')

      expect(mockFs.mkdir).toHaveBeenCalledWith(
        expect.stringContaining('.vaultkeeper'),
        expect.objectContaining({ recursive: true }),
      )
      expect(mockExecCommand).toHaveBeenCalledWith(
        'powershell',
        expect.arrayContaining(['-NoProfile', '-Command']),
      )
    })

    it('should include the secret in the powershell script', async () => {
      mockFs.mkdir.mockResolvedValue(undefined)
      mockExecCommand.mockResolvedValue('')

      await backend.store('test-id', 'my-secret-value')

      const callArgs = mockExecCommand.mock.calls[0]
      const script = callArgs?.[1]?.find(
        (arg) => typeof arg === 'string' && arg.includes('my-secret-value'),
      )
      expect(script).toBeDefined()
    })

    // Regression: issue #60 — BackendConfig.path was silently ignored.
    it('should honor a custom storage path from config', async () => {
      const customDir = path.join(path.sep, 'custom', 'dpapi', 'dir')
      const customBackend = new DpapiBackend(customDir)
      mockFs.mkdir.mockResolvedValue(undefined)
      mockExecCommand.mockResolvedValue('')

      await customBackend.store('my-secret', 'secret-value')

      expect(mockFs.mkdir).toHaveBeenCalledWith(
        customDir,
        expect.objectContaining({ recursive: true }),
      )
      const writePathArg = mockExecCommand.mock.calls[0]?.[1]?.find(
        (arg) => typeof arg === 'string' && arg.includes(customDir),
      )
      expect(writePathArg).toBeDefined()
    })
  })

  describe('retrieve', () => {
    it('should run powershell decrypt when file exists', async () => {
      mockFs.access.mockResolvedValue(undefined)
      mockExecCommand.mockResolvedValue('decrypted-secret')

      const result = await backend.retrieve('my-secret')
      expect(result).toBe('decrypted-secret')
    })

    it('should throw SecretNotFoundError when file does not exist', async () => {
      const fsError = Object.assign(new Error('ENOENT'), { code: 'ENOENT' })
      mockFs.access.mockRejectedValue(fsError)

      await expect(backend.retrieve('missing')).rejects.toBeInstanceOf(SecretNotFoundError)
    })
  })

  describe('delete', () => {
    it('should unlink the encrypted file', async () => {
      mockFs.unlink.mockResolvedValue(undefined)

      await backend.delete('my-secret')

      expect(mockFs.unlink).toHaveBeenCalledWith(expect.stringContaining('.vaultkeeper'))
    })

    it('should throw SecretNotFoundError when file does not exist', async () => {
      const fsError = Object.assign(new Error('ENOENT'), { code: 'ENOENT' })
      mockFs.unlink.mockRejectedValue(fsError)

      await expect(backend.delete('missing')).rejects.toBeInstanceOf(SecretNotFoundError)
    })

    // Regression for the #127/#164 review: a non-ENOENT unlink failure
    // previously rethrew the raw Node error, escaping the VaultError
    // hierarchy — the same contract gap #126 fixed in FileBackend.delete.
    it('wraps a non-ENOENT unlink failure (e.g. EACCES) as a typed FilesystemError', async () => {
      const fsError = Object.assign(new Error('EACCES: permission denied'), { code: 'EACCES' })
      mockFs.unlink.mockRejectedValueOnce(fsError)

      const caught = await backend.delete('protected').then(
        () => undefined,
        (err: unknown) => err,
      )
      expect(caught).toBeInstanceOf(FilesystemError)
      if (caught instanceof FilesystemError) {
        expect(caught.permission).toBe('delete')
        expect(caught.code).toBe('EACCES')
        expect(caught.cause).toBe(fsError)
      }
    })

    it('should rethrow non-ENOENT errors', async () => {
      const permError = Object.assign(new Error('EPERM'), { code: 'EPERM' })
      mockFs.unlink.mockRejectedValue(permError)

      await expect(backend.delete('protected')).rejects.toThrow('EPERM')
    })
  })

  describe('exists', () => {
    it('should return true when file exists', async () => {
      mockFs.access.mockResolvedValue(undefined)

      const result = await backend.exists('my-secret')
      expect(result).toBe(true)
    })

    it('should return false when file does not exist', async () => {
      mockFs.access.mockRejectedValue(new Error('ENOENT'))

      const result = await backend.exists('missing')
      expect(result).toBe(false)
    })
  })

  describe('list', () => {
    it('should return decoded secret ids for all .enc files', async () => {
      const id1 = 'my-secret'
      const id2 = 'another-secret'
      const hex1 = Buffer.from(id1, 'utf8').toString('hex')
      const hex2 = Buffer.from(id2, 'utf8').toString('hex')
      mockFs.readdir.mockResolvedValue([`${hex1}.enc`, `${hex2}.enc`, 'other.txt'])

      const result = await backend.list()
      expect(result).toEqual([id1, id2])
    })

    it('should return empty array when storage directory does not exist', async () => {
      mockFs.readdir.mockRejectedValue(Object.assign(new Error('ENOENT'), { code: 'ENOENT' }))

      const result = await backend.list()
      expect(result).toEqual([])
    })

    it('should return empty array when directory contains no .enc files', async () => {
      mockFs.readdir.mockResolvedValue(['readme.txt', 'metadata.json'])

      const result = await backend.list()
      expect(result).toEqual([])
    })
  })
})
