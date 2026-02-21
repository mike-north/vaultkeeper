import { describe, it, expect, vi, beforeEach } from 'vitest'
import type { ExecCommandResult } from '../../../src/util/exec.js'

vi.mock('../../../src/util/exec.js', () => ({
  execCommand: vi.fn(),
  execCommandFull: vi.fn(),
}))

vi.mock('node:fs/promises', () => ({
  mkdir: vi.fn(),
  access: vi.fn(),
  unlink: vi.fn(),
}))

import * as fs from 'node:fs/promises'
import { execCommand, execCommandFull } from '../../../src/util/exec.js'
import { DpapiBackend } from '../../../src/backend/dpapi-backend.js'
import { SecretNotFoundError } from '../../../src/errors.js'

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
})
