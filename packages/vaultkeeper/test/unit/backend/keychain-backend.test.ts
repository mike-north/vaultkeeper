import { describe, it, expect, vi, beforeEach } from 'vitest'
import type { ExecCommandResult } from '../../../src/util/exec.js'

vi.mock('../../../src/util/exec.js', () => ({
  execCommand: vi.fn(),
  execCommandFull: vi.fn(),
}))

import { execCommand, execCommandFull } from '../../../src/util/exec.js'
import { KeychainBackend } from '../../../src/backend/keychain-backend.js'
import { SecretNotFoundError } from '../../../src/errors.js'

const mockExecCommand = vi.mocked(execCommand)
const mockExecCommandFull = vi.mocked(execCommandFull)

function makeResult(exitCode: number, stdout = '', stderr = ''): ExecCommandResult {
  return { exitCode, stdout, stderr }
}

describe('KeychainBackend', () => {
  let backend: KeychainBackend

  beforeEach(() => {
    backend = new KeychainBackend()
    vi.clearAllMocks()
  })

  describe('isAvailable', () => {
    it('should return true on darwin when security succeeds', async () => {
      const originalPlatform = process.platform
      Object.defineProperty(process, 'platform', { value: 'darwin', configurable: true })
      mockExecCommandFull.mockResolvedValue(makeResult(0, 'SecureTransport-55471.20.5'))

      const result = await backend.isAvailable()
      expect(result).toBe(true)

      Object.defineProperty(process, 'platform', { value: originalPlatform, configurable: true })
    })

    it('should return false on non-darwin platforms', async () => {
      const originalPlatform = process.platform
      Object.defineProperty(process, 'platform', { value: 'linux', configurable: true })

      const result = await backend.isAvailable()
      expect(result).toBe(false)

      Object.defineProperty(process, 'platform', { value: originalPlatform, configurable: true })
    })

    it('should return false when security command fails', async () => {
      const originalPlatform = process.platform
      Object.defineProperty(process, 'platform', { value: 'darwin', configurable: true })
      mockExecCommandFull.mockRejectedValue(new Error('command not found'))

      const result = await backend.isAvailable()
      expect(result).toBe(false)

      Object.defineProperty(process, 'platform', { value: originalPlatform, configurable: true })
    })
  })

  describe('store', () => {
    it('should delete existing entry then add new one', async () => {
      mockExecCommandFull.mockResolvedValue(makeResult(0))
      mockExecCommand.mockResolvedValue('')

      await backend.store('my-secret', 'secret-value')

      // Delete call
      expect(mockExecCommandFull).toHaveBeenCalledWith('security', [
        'delete-generic-password',
        '-a',
        'vaultkeeper',
        '-s',
        'vaultkeeper:my-secret',
      ])

      // Add call - check base64 encoding
      const encoded = Buffer.from('secret-value', 'utf8').toString('base64')
      expect(mockExecCommand).toHaveBeenCalledWith('security', [
        'add-generic-password',
        '-a',
        'vaultkeeper',
        '-s',
        'vaultkeeper:my-secret',
        '-w',
        encoded,
      ])
    })

    it('should base64-encode the secret value', async () => {
      mockExecCommandFull.mockResolvedValue(makeResult(0))
      mockExecCommand.mockResolvedValue('')

      const secret = 'my-special-secret-with-special-chars: !@#$'
      await backend.store('test-id', secret)

      const encoded = Buffer.from(secret, 'utf8').toString('base64')
      expect(mockExecCommand).toHaveBeenCalledWith(
        'security',
        expect.arrayContaining(['-w', encoded]),
      )
    })
  })

  describe('retrieve', () => {
    it('should decode base64 and return the secret', async () => {
      const secret = 'decoded-secret-value'
      const encoded = Buffer.from(secret, 'utf8').toString('base64')
      mockExecCommandFull.mockResolvedValue(makeResult(0, `${encoded}\n`))

      const result = await backend.retrieve('my-secret')
      expect(result).toBe(secret)
    })

    it('should throw SecretNotFoundError when exitCode is non-zero', async () => {
      mockExecCommandFull.mockResolvedValue(makeResult(1, '', 'could not be found'))

      await expect(backend.retrieve('missing-secret')).rejects.toBeInstanceOf(SecretNotFoundError)
    })

    it('should use correct service name in lookup', async () => {
      const encoded = Buffer.from('val', 'utf8').toString('base64')
      mockExecCommandFull.mockResolvedValue(makeResult(0, encoded))

      await backend.retrieve('test-id')

      expect(mockExecCommandFull).toHaveBeenCalledWith('security', [
        'find-generic-password',
        '-a',
        'vaultkeeper',
        '-s',
        'vaultkeeper:test-id',
        '-w',
      ])
    })
  })

  describe('delete', () => {
    it('should call security delete-generic-password', async () => {
      mockExecCommandFull.mockResolvedValue(makeResult(0))

      await backend.delete('my-secret')

      expect(mockExecCommandFull).toHaveBeenCalledWith('security', [
        'delete-generic-password',
        '-a',
        'vaultkeeper',
        '-s',
        'vaultkeeper:my-secret',
      ])
    })

    it('should throw SecretNotFoundError when secret does not exist', async () => {
      mockExecCommandFull.mockResolvedValue(makeResult(44, '', 'could not be found'))

      await expect(backend.delete('missing-secret')).rejects.toBeInstanceOf(SecretNotFoundError)
    })
  })

  describe('exists', () => {
    it('should return true when secret exists', async () => {
      mockExecCommandFull.mockResolvedValue(makeResult(0))

      const result = await backend.exists('my-secret')
      expect(result).toBe(true)
    })

    it('should return false when secret does not exist', async () => {
      mockExecCommandFull.mockResolvedValue(makeResult(44, '', 'not found'))

      const result = await backend.exists('missing-secret')
      expect(result).toBe(false)
    })
  })

  describe('list', () => {
    it('should parse service names from dump-keychain output', async () => {
      const dumpOutput = [
        'keychain: "/Users/test/Library/Keychains/login.keychain-db"',
        'class: "genp"',
        '    0x00000007 <blob>="vaultkeeper:api-key"',
        '    "acct"<blob>="vaultkeeper"',
        'class: "genp"',
        '    0x00000007 <blob>="vaultkeeper:db-password"',
        '    "acct"<blob>="vaultkeeper"',
        'class: "genp"',
        '    0x00000007 <blob>="some-other-service"',
      ].join('\n')
      mockExecCommandFull.mockResolvedValue(makeResult(0, dumpOutput))

      const result = await backend.list()
      expect(result).toEqual(['api-key', 'db-password'])
    })

    it('should return an empty array when dump-keychain fails', async () => {
      mockExecCommandFull.mockResolvedValue(makeResult(1, '', 'error'))

      const result = await backend.list()
      expect(result).toEqual([])
    })

    it('should return an empty array when no vaultkeeper entries exist', async () => {
      const dumpOutput = [
        'class: "genp"',
        '    0x00000007 <blob>="some-other-service"',
      ].join('\n')
      mockExecCommandFull.mockResolvedValue(makeResult(0, dumpOutput))

      const result = await backend.list()
      expect(result).toEqual([])
    })
  })
})
