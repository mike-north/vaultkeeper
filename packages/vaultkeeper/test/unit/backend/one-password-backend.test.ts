import { describe, it, expect, vi, beforeEach } from 'vitest'
import type { ExecCommandResult } from '../../../src/util/exec.js'

vi.mock('../../../src/util/exec.js', () => ({
  execCommand: vi.fn(),
  execCommandFull: vi.fn(),
}))

import { execCommand, execCommandFull } from '../../../src/util/exec.js'
import { OnePasswordBackend } from '../../../src/backend/one-password-backend.js'
import { SecretNotFoundError, PluginNotFoundError } from '../../../src/errors.js'

const mockExecCommand = vi.mocked(execCommand)
const mockExecCommandFull = vi.mocked(execCommandFull)

function makeResult(exitCode: number, stdout = '', stderr = ''): ExecCommandResult {
  return { exitCode, stdout, stderr }
}

describe('OnePasswordBackend', () => {
  let backend: OnePasswordBackend

  beforeEach(() => {
    backend = new OnePasswordBackend()
    vi.clearAllMocks()
  })

  describe('isAvailable', () => {
    it('should return true when op is available', async () => {
      mockExecCommandFull.mockResolvedValue(makeResult(0, '2.24.0'))

      const result = await backend.isAvailable()
      expect(result).toBe(true)
    })

    it('should return false when op is not installed', async () => {
      mockExecCommandFull.mockRejectedValue(new Error('command not found: op'))

      const result = await backend.isAvailable()
      expect(result).toBe(false)
    })

    it('should return false when op exits with non-zero', async () => {
      mockExecCommandFull.mockResolvedValue(makeResult(1))

      const result = await backend.isAvailable()
      expect(result).toBe(false)
    })
  })

  describe('store', () => {
    it('should create new item when secret does not exist', async () => {
      // isAvailable check
      mockExecCommandFull
        .mockResolvedValueOnce(makeResult(0, '2.24.0')) // isAvailable
        .mockResolvedValueOnce(makeResult(1)) // exists check (not found)
      mockExecCommand.mockResolvedValue('')

      await backend.store('my-secret', 'secret-value')

      expect(mockExecCommand).toHaveBeenCalledWith(
        'op',
        expect.arrayContaining(['item', 'create', '--category', 'Password', '--title', 'my-secret']),
      )
    })

    it('should edit existing item when secret already exists', async () => {
      // store calls: isAvailable, then exists (which calls isAvailable again + item get)
      mockExecCommandFull
        .mockResolvedValueOnce(makeResult(0, '2.24.0')) // store -> isAvailable
        .mockResolvedValueOnce(makeResult(0, '2.24.0')) // exists -> isAvailable
        .mockResolvedValueOnce(makeResult(0, 'my-secret')) // exists -> item get (found)
      mockExecCommand.mockResolvedValue('')

      await backend.store('my-secret', 'new-value')

      expect(mockExecCommand).toHaveBeenCalledWith(
        'op',
        expect.arrayContaining(['item', 'edit', 'my-secret']),
      )
    })

    it('should include vault args when vault is specified', async () => {
      const vaultBackend = new OnePasswordBackend('my-vault')

      mockExecCommandFull
        .mockResolvedValueOnce(makeResult(0)) // isAvailable
        .mockResolvedValueOnce(makeResult(1)) // exists check (not found)
      mockExecCommand.mockResolvedValue('')

      await vaultBackend.store('my-secret', 'value')

      expect(mockExecCommand).toHaveBeenCalledWith(
        'op',
        expect.arrayContaining(['--vault', 'my-vault']),
      )
    })

    it('should throw PluginNotFoundError when op is not available', async () => {
      mockExecCommandFull.mockRejectedValue(new Error('command not found'))

      await expect(backend.store('my-secret', 'value')).rejects.toBeInstanceOf(PluginNotFoundError)
    })
  })

  describe('retrieve', () => {
    it('should return the secret value', async () => {
      mockExecCommandFull
        .mockResolvedValueOnce(makeResult(0)) // isAvailable
        .mockResolvedValueOnce(makeResult(0, 'my-secret-value\n')) // item get

      const result = await backend.retrieve('my-secret')
      expect(result).toBe('my-secret-value')
    })

    it('should throw SecretNotFoundError when item does not exist', async () => {
      mockExecCommandFull
        .mockResolvedValueOnce(makeResult(0)) // isAvailable
        .mockResolvedValueOnce(makeResult(1, '', '[ERROR] 2024/01/01 item not found')) // item get

      await expect(backend.retrieve('missing')).rejects.toBeInstanceOf(SecretNotFoundError)
    })

    it('should throw PluginNotFoundError when op is not available', async () => {
      mockExecCommandFull.mockRejectedValue(new Error('command not found'))

      await expect(backend.retrieve('my-secret')).rejects.toBeInstanceOf(PluginNotFoundError)
    })
  })

  describe('delete', () => {
    it('should delete the item successfully', async () => {
      mockExecCommandFull
        .mockResolvedValueOnce(makeResult(0)) // isAvailable
        .mockResolvedValueOnce(makeResult(0)) // item delete

      await backend.delete('my-secret')

      expect(mockExecCommandFull).toHaveBeenCalledWith(
        'op',
        expect.arrayContaining(['item', 'delete', 'my-secret']),
      )
    })

    it('should throw SecretNotFoundError when item does not exist', async () => {
      mockExecCommandFull
        .mockResolvedValueOnce(makeResult(0)) // isAvailable
        .mockResolvedValueOnce(makeResult(1, '', 'item not found')) // item delete

      await expect(backend.delete('missing')).rejects.toBeInstanceOf(SecretNotFoundError)
    })
  })

  describe('exists', () => {
    it('should return true when item exists', async () => {
      mockExecCommandFull
        .mockResolvedValueOnce(makeResult(0)) // isAvailable
        .mockResolvedValueOnce(makeResult(0, 'my-secret')) // item get

      const result = await backend.exists('my-secret')
      expect(result).toBe(true)
    })

    it('should return false when item does not exist', async () => {
      mockExecCommandFull
        .mockResolvedValueOnce(makeResult(0)) // isAvailable
        .mockResolvedValueOnce(makeResult(1)) // item get

      const result = await backend.exists('missing')
      expect(result).toBe(false)
    })

    it('should return false when op is not available', async () => {
      mockExecCommandFull.mockRejectedValue(new Error('command not found'))

      const result = await backend.exists('my-secret')
      expect(result).toBe(false)
    })
  })
})
