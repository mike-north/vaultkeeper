import { describe, it, expect, vi, beforeEach } from 'vitest'
import type { ExecCommandResult } from '../../../src/util/exec.js'

vi.mock('../../../src/util/exec.js', () => ({
  execCommand: vi.fn(),
  execCommandFull: vi.fn(),
}))

import { execCommand, execCommandFull } from '../../../src/util/exec.js'
import { SecretToolBackend } from '../../../src/backend/secret-tool-backend.js'
import { SecretNotFoundError } from '../../../src/errors.js'

const mockExecCommand = vi.mocked(execCommand)
const mockExecCommandFull = vi.mocked(execCommandFull)

function makeResult(exitCode: number, stdout = '', stderr = ''): ExecCommandResult {
  return { exitCode, stdout, stderr }
}

describe('SecretToolBackend', () => {
  let backend: SecretToolBackend

  beforeEach(() => {
    backend = new SecretToolBackend()
    vi.clearAllMocks()
  })

  describe('isAvailable', () => {
    it('should return true on linux when secret-tool is available', async () => {
      const originalPlatform = process.platform
      Object.defineProperty(process, 'platform', { value: 'linux', configurable: true })
      mockExecCommandFull.mockResolvedValue(makeResult(0, 'secret-tool 0.18'))

      const result = await backend.isAvailable()
      expect(result).toBe(true)

      Object.defineProperty(process, 'platform', { value: originalPlatform, configurable: true })
    })

    it('should return false on non-linux platforms', async () => {
      const originalPlatform = process.platform
      Object.defineProperty(process, 'platform', { value: 'darwin', configurable: true })

      const result = await backend.isAvailable()
      expect(result).toBe(false)

      Object.defineProperty(process, 'platform', { value: originalPlatform, configurable: true })
    })

    it('should return false when secret-tool is not installed', async () => {
      const originalPlatform = process.platform
      Object.defineProperty(process, 'platform', { value: 'linux', configurable: true })
      mockExecCommandFull.mockRejectedValue(new Error('command not found: secret-tool'))

      const result = await backend.isAvailable()
      expect(result).toBe(false)

      Object.defineProperty(process, 'platform', { value: originalPlatform, configurable: true })
    })
  })

  describe('store', () => {
    it('should call secret-tool store with correct arguments', async () => {
      mockExecCommand.mockResolvedValue('')

      await backend.store('my-secret', 'secret-value')

      expect(mockExecCommand).toHaveBeenCalledWith(
        'secret-tool',
        ['store', '--label', 'vaultkeeper: my-secret', 'vaultkeeper-id', 'my-secret'],
        { stdin: 'secret-value' },
      )
    })

    it('should pass secret via stdin', async () => {
      mockExecCommand.mockResolvedValue('')

      await backend.store('test-id', 'my-password')

      const callArgs = mockExecCommand.mock.calls[0]
      expect(callArgs?.[2]).toEqual({ stdin: 'my-password' })
    })
  })

  describe('retrieve', () => {
    it('should return trimmed stdout on success', async () => {
      mockExecCommandFull.mockResolvedValue(makeResult(0, 'secret-value\n'))

      const result = await backend.retrieve('my-secret')
      expect(result).toBe('secret-value')
    })

    it('should throw SecretNotFoundError when exitCode is non-zero', async () => {
      mockExecCommandFull.mockResolvedValue(makeResult(1, '', 'No matching items found'))

      await expect(backend.retrieve('missing')).rejects.toBeInstanceOf(SecretNotFoundError)
    })

    it('should throw SecretNotFoundError when stdout is empty', async () => {
      mockExecCommandFull.mockResolvedValue(makeResult(0, '  \n'))

      await expect(backend.retrieve('empty-secret')).rejects.toBeInstanceOf(SecretNotFoundError)
    })
  })

  describe('delete', () => {
    it('should call secret-tool clear with correct arguments', async () => {
      mockExecCommandFull.mockResolvedValue(makeResult(0))

      await backend.delete('my-secret')

      expect(mockExecCommandFull).toHaveBeenCalledWith('secret-tool', [
        'clear',
        'vaultkeeper-id',
        'my-secret',
      ])
    })

    it('should throw SecretNotFoundError when secret does not exist', async () => {
      mockExecCommandFull.mockResolvedValue(makeResult(1, '', 'No matching items found'))

      await expect(backend.delete('missing')).rejects.toBeInstanceOf(SecretNotFoundError)
    })
  })

  describe('exists', () => {
    it('should return true when secret exists', async () => {
      mockExecCommandFull.mockResolvedValue(makeResult(0, 'some-secret'))

      const result = await backend.exists('my-secret')
      expect(result).toBe(true)
    })

    it('should return false when lookup returns empty', async () => {
      mockExecCommandFull.mockResolvedValue(makeResult(0, ''))

      const result = await backend.exists('no-secret')
      expect(result).toBe(false)
    })

    it('should return false when lookup fails', async () => {
      mockExecCommandFull.mockResolvedValue(makeResult(1, '', 'not found'))

      const result = await backend.exists('missing')
      expect(result).toBe(false)
    })
  })

  describe('list', () => {
    it('should parse vaultkeeper-id attributes from secret-tool search output', async () => {
      const stdout = [
        '[/org/freedesktop/secrets/collection/login/1]',
        'label = vaultkeeper: my-secret',
        'secret = ',
        'created = 2024-01-01 00:00:00',
        'modified = 2024-01-01 00:00:00',
        'schema: org.freedesktop.Secret.Generic',
        'attribute.vaultkeeper-id = my-secret',
        '',
        '[/org/freedesktop/secrets/collection/login/2]',
        'label = vaultkeeper: another-secret',
        'secret = ',
        'attribute.vaultkeeper-id = another-secret',
      ].join('\n')

      mockExecCommandFull.mockResolvedValue(makeResult(0, stdout))

      const result = await backend.list()
      expect(result).toEqual(['my-secret', 'another-secret'])
    })

    it('should return empty array when secret-tool search command fails', async () => {
      mockExecCommandFull.mockResolvedValue(makeResult(1, '', 'No matching items found'))

      const result = await backend.list()
      expect(result).toEqual([])
    })

    it('should return empty array when search output has no matching entries', async () => {
      mockExecCommandFull.mockResolvedValue(makeResult(0, 'No items found\n'))

      const result = await backend.list()
      expect(result).toEqual([])
    })
  })
})
