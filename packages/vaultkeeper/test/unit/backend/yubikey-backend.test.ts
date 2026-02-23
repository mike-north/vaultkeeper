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
  readFile: vi.fn(),
  writeFile: vi.fn(),
}))

import * as fs from 'node:fs/promises'
import { execCommand, execCommandFull } from '../../../src/util/exec.js'
import { YubikeyBackend } from '../../../src/backend/yubikey-backend.js'
import {
  SecretNotFoundError,
  PluginNotFoundError,
  DeviceNotPresentError,
} from '../../../src/errors.js'

const mockExecCommand = vi.mocked(execCommand)
const mockExecCommandFull = vi.mocked(execCommandFull)
const mockFs = vi.mocked(fs)

function makeResult(exitCode: number, stdout = '', stderr = ''): ExecCommandResult {
  return { exitCode, stdout, stderr }
}

describe('YubikeyBackend', () => {
  let backend: YubikeyBackend

  beforeEach(() => {
    backend = new YubikeyBackend()
    vi.clearAllMocks()
  })

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

  describe('store', () => {
    it('should perform challenge-response and encrypt secret', async () => {
      // isAvailable calls (ykman --version + ykman list)
      mockExecCommandFull
        .mockResolvedValueOnce(makeResult(0, 'ykman 5.4.0'))
        .mockResolvedValueOnce(makeResult(0, 'YubiKey 5 NFC'))
        .mockResolvedValueOnce(makeResult(0, 'abcdef123456')) // otp calculate

      mockFs.mkdir.mockResolvedValue(undefined)
      mockFs.readFile.mockRejectedValue(Object.assign(new Error('ENOENT'), { code: 'ENOENT' }))
      mockFs.writeFile.mockResolvedValue(undefined)
      mockExecCommand.mockResolvedValue('')

      await backend.store('my-secret', 'secret-value')

      expect(mockExecCommandFull).toHaveBeenCalledWith('ykman', [
        'otp',
        'calculate',
        '2',
        expect.any(String),
      ])
      // The derived key and secret are passed to openssl via stdin (not the command line)
      // to avoid leaking the key in the process table.
      const opensslCall = mockExecCommand.mock.calls.find(([cmd]) => cmd === 'openssl')
      expect(opensslCall).toBeDefined()
      const opensslArgs: string[] = opensslCall?.[1] ?? []
      expect(opensslArgs).toContain('enc')
      expect(opensslArgs).toContain('-aes-256-cbc')
      expect(opensslArgs).toContain('-pass')
      expect(opensslArgs).toContain('stdin')
      // Verify that the passphrase is NOT visible in the args (it must be in stdin).
      const callArgs = mockExecCommand.mock.calls[0]
      expect(callArgs).toBeDefined()
      const [_cmd, args, opts] = callArgs ?? []
      expect(args?.join(' ')).not.toContain('abcdef123456')
      const stdinValue: unknown =
        opts !== undefined && typeof opts === 'object' && 'stdin' in opts
          ? opts.stdin
          : undefined
      expect(typeof stdinValue).toBe('string')
      if (typeof stdinValue === 'string') {
        expect(stdinValue).toContain('secret-value')
      }
    })

    it('should throw PluginNotFoundError when ykman is not installed', async () => {
      // isAvailable fails (no ykman) then requireDevice re-checks ykman
      mockExecCommandFull.mockRejectedValue(new Error('command not found'))

      await expect(backend.store('my-secret', 'value')).rejects.toBeInstanceOf(PluginNotFoundError)
    })

    it('should throw DeviceNotPresentError when no device is connected', async () => {
      // isAvailable: ykman available but no device
      mockExecCommandFull
        .mockResolvedValueOnce(makeResult(0, '')) // isAvailable ykman --version returns nothing → non-zero...
      // Actually: first call returns exit 0 with no stdout → list returns empty → isAvailable = false
      // Then requireDevice checks ykman --version again
      mockExecCommandFull
        .mockReset()
        .mockResolvedValueOnce(makeResult(0, 'ykman 5.4.0')) // isAvailable ykman --version
        .mockResolvedValueOnce(makeResult(0, '')) // ykman list → empty → isAvailable false
        .mockResolvedValueOnce(makeResult(0, 'ykman 5.4.0')) // requireDevice hasYkman check

      await expect(backend.store('my-secret', 'value')).rejects.toBeInstanceOf(
        DeviceNotPresentError,
      )
    })
  })

  describe('retrieve', () => {
    it('should throw SecretNotFoundError when file does not exist', async () => {
      mockExecCommandFull
        .mockResolvedValueOnce(makeResult(0, 'ykman 5.4.0'))
        .mockResolvedValueOnce(makeResult(0, 'YubiKey 5 NFC'))

      mockFs.access.mockRejectedValue(Object.assign(new Error('ENOENT'), { code: 'ENOENT' }))

      await expect(backend.retrieve('missing')).rejects.toBeInstanceOf(SecretNotFoundError)
    })

    it('should decrypt and return the secret when device is available', async () => {
      mockExecCommandFull
        .mockResolvedValueOnce(makeResult(0, 'ykman 5.4.0'))
        .mockResolvedValueOnce(makeResult(0, 'YubiKey 5 NFC'))
        .mockResolvedValueOnce(makeResult(0, 'abcdef123456')) // challenge response
        .mockResolvedValueOnce(makeResult(0, 'decrypted-secret')) // openssl decrypt

      mockFs.access.mockResolvedValue(undefined)

      const result = await backend.retrieve('my-secret')
      expect(result).toBe('decrypted-secret')
    })
  })

  describe('delete', () => {
    it('should unlink the file when it exists', async () => {
      mockExecCommandFull
        .mockResolvedValueOnce(makeResult(0, 'ykman 5.4.0'))
        .mockResolvedValueOnce(makeResult(0, 'YubiKey 5 NFC'))

      mockFs.unlink.mockResolvedValue(undefined)
      mockFs.readFile.mockRejectedValue(Object.assign(new Error('ENOENT'), { code: 'ENOENT' }))
      mockFs.writeFile.mockResolvedValue(undefined)

      await backend.delete('my-secret')

      expect(mockFs.unlink).toHaveBeenCalledWith(expect.stringContaining('.enc'))
    })

    it('should throw SecretNotFoundError when file does not exist', async () => {
      mockExecCommandFull
        .mockResolvedValueOnce(makeResult(0, 'ykman 5.4.0'))
        .mockResolvedValueOnce(makeResult(0, 'YubiKey 5 NFC'))

      const noFileError = Object.assign(new Error('ENOENT'), { code: 'ENOENT' })
      mockFs.unlink.mockRejectedValue(noFileError)

      await expect(backend.delete('missing')).rejects.toBeInstanceOf(SecretNotFoundError)
    })
  })

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

  describe('list', () => {
    it('should return all entry keys from metadata file', async () => {
      const metadata = { entries: { 'my-secret': '/path/a.enc', 'another-secret': '/path/b.enc' } }
      mockFs.readFile.mockResolvedValue(JSON.stringify(metadata))

      const result = await backend.list()
      expect(result).toEqual(['my-secret', 'another-secret'])
    })

    it('should return empty array when metadata file does not exist', async () => {
      // loadMetadata catches errors and returns { entries: {} }
      mockFs.readFile.mockRejectedValue(Object.assign(new Error('ENOENT'), { code: 'ENOENT' }))

      const result = await backend.list()
      expect(result).toEqual([])
    })

    it('should return empty array when metadata has no entries', async () => {
      const metadata = { entries: {} }
      mockFs.readFile.mockResolvedValue(JSON.stringify(metadata))

      const result = await backend.list()
      expect(result).toEqual([])
    })
  })
})
