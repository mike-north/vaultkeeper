import { describe, it, expect, vi, beforeEach } from 'vitest'
import type { ExecCommandResult } from '../../../src/util/exec.js'

vi.mock('../../../src/util/exec.js', () => ({
  execCommand: vi.fn(),
  execCommandFull: vi.fn(),
}))

import { execCommand, execCommandFull } from '../../../src/util/exec.js'
import { KeychainBackend } from '../../../src/backend/keychain-backend.js'
import { KEYCHAIN_CONFIRM_MISS_SCRIPT } from '../../../src/backend/keychain-confirm-miss.js'
import { KEYCHAIN_UPDATE_SCRIPT } from '../../../src/backend/keychain-update.js'
import { ExecError, SecretNotFoundError } from '../../../src/errors.js'

const mockExecCommand = vi.mocked(execCommand)
const mockExecCommandFull = vi.mocked(execCommandFull)

function makeResult(exitCode: number, stdout = '', stderr = ''): ExecCommandResult {
  return { exitCode, stdout, stderr }
}

/** Keep the original item in a non-default keychain. */
function mockKeychain() {
  const path = '/test/team clés.keychain-db'
  const metadata = `keychain: 0x${Buffer.from(path).toString('hex')}  "/test/display"\nversion: 512\n`
  let entry: string | undefined
  let shadow: string | undefined
  let rejected = false
  let ownerUnavailable = false
  let ownerLostDuringLookup = false
  let serviceName = 'vaultkeeper:my-secret'
  mockExecCommandFull.mockImplementation((cmd, args, options) => {
    if (args[0] === 'find-generic-password') {
      if (ownerLostDuringLookup) {
        return Promise.resolve(
          makeResult(
            44,
            '',
            'security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain.\n',
          ),
        )
      }
      return Promise.resolve(
        entry === undefined
          ? makeResult(44)
          : makeResult(0, args.includes('-w') ? entry : metadata),
      )
    }
    if (args[0] === 'delete-generic-password') {
      entry = undefined
      return Promise.resolve(makeResult(0))
    }
    if (cmd === '/usr/bin/osascript') {
      const value = options?.stdin
      const [, , , script, , target, service, account, size] = args
      if (script === KEYCHAIN_CONFIRM_MISS_SCRIPT) {
        if (target !== serviceName || service !== 'vaultkeeper' || value !== undefined) {
          return Promise.resolve(makeResult(2))
        }
        const status = ownerLostDuringLookup ? '-25294' : entry === undefined ? 'absent' : 'present'
        return Promise.resolve(makeResult(0, `${status}\n`))
      }
      if (
        script !== KEYCHAIN_UPDATE_SCRIPT ||
        target !== path ||
        service !== serviceName ||
        account !== 'vaultkeeper' ||
        value === undefined ||
        String(value.length) !== size
      ) {
        return Promise.resolve(makeResult(2))
      }
      // The runner exits zero after reporting a native status, even if the item disappeared.
      if (ownerUnavailable || entry === undefined) return Promise.resolve(makeResult(0, '-25300\n'))
      if (rejected) return Promise.resolve(makeResult(0, '-25293\n'))
      entry = value
      return Promise.resolve(makeResult(0, '0\n'))
    }
    const write =
      /^add-generic-password (-U )?-a "vaultkeeper" -s "vaultkeeper:my-secret" -w "([^"]*)"(?: "([^"]+)")?\n$/.exec(
        options?.stdin ?? '',
      )
    if (args[0] !== '-i' || write === null) return Promise.resolve(makeResult(2))
    const [, update, value, target] = write
    if (ownerLostDuringLookup) {
      // An ordinary add succeeds in the default even though the hidden owner still has the item.
      shadow = value
      return Promise.resolve(makeResult(0))
    }
    if (ownerUnavailable && update !== undefined) {
      // An explicit target does not prevent Apple's fallback add redirecting to the default.
      shadow = value
      return Promise.resolve(makeResult(0))
    }
    if (rejected && update !== undefined && target !== path) {
      // security can report success after a fallback add in the default keychain.
      shadow = value
      return Promise.resolve(makeResult(0))
    }
    if (rejected || (entry !== undefined && target !== path)) {
      return Promise.resolve(makeResult(45, '', `update rejected: ${value ?? ''}`))
    }
    entry = value
    return Promise.resolve(makeResult(0))
  })
  // Model the old write too, so the regression test reaches the read on main.
  mockExecCommand.mockImplementation((_cmd, args) => {
    if (rejected) return Promise.reject(new ExecError('update rejected', 'security'))
    entry = args.at(-1)
    return Promise.resolve('')
  })
  return {
    seedLegacy: (id: string, value: string) => {
      serviceName = `vaultkeeper:${id}`
      entry = Buffer.from(value).toString('base64')
    },
    rejectWrites: () => {
      rejected = true
    },
    setOwnerUnavailable: (unavailable: boolean) => {
      ownerUnavailable = unavailable
    },
    setOwnerLostDuringLookup: (unavailable: boolean) => {
      ownerLostDuringLookup = unavailable
    },
    hasShadow: () => shadow !== undefined,
  }
}

describe('KeychainBackend', () => {
  let backend: KeychainBackend

  beforeEach(() => {
    backend = new KeychainBackend()
    vi.resetAllMocks()
  })

  describe('isAvailable', () => {
    it('should return true on darwin when security succeeds', async () => {
      const originalPlatform = process.platform
      Object.defineProperty(process, 'platform', { value: 'darwin', configurable: true })
      mockExecCommandFull.mockResolvedValue(makeResult(0, '"/test/login.keychain-db"\n'))

      const result = await backend.isAvailable()
      expect(result).toBe(true)
      expect(mockExecCommandFull).toHaveBeenCalledWith('security', ['list-keychains'])

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
    it('preserves the exact prior credential if replacement fails', async () => {
      const keychain = mockKeychain()
      const prior = 'still-valid-🔐\ncredential'
      await backend.store('my-secret', prior)
      keychain.rejectWrites()

      await expect(backend.store('my-secret', 'rejected')).rejects.toThrow(ExecError)
      await expect(backend.retrieve('my-secret')).resolves.toBe(prior)
      expect(keychain.hasShadow()).toBe(false)
    })

    it('fails without a default-keychain copy if the owner disappears after lookup', async () => {
      const keychain = mockKeychain()
      const prior = 'still-valid-🔐\ncredential'
      await backend.store('my-secret', prior)
      keychain.setOwnerUnavailable(true)

      await expect(backend.store('my-secret', 'replacement')).rejects.toThrow(ExecError)
      keychain.setOwnerUnavailable(false)
      await expect(backend.retrieve('my-secret')).resolves.toBe(prior)
      expect(keychain.hasShadow()).toBe(false)
    })

    it('fails without a default-keychain copy if lookup silently skips the owner', async () => {
      const keychain = mockKeychain()
      const prior = 'still-valid-🔐\ncredential'
      await backend.store('my-secret', prior)
      keychain.setOwnerLostDuringLookup(true)

      await expect(backend.store('my-secret', 'replacement')).rejects.toThrow(/confirm.*absent/)
      keychain.setOwnerLostDuringLookup(false)

      expect(keychain.hasShadow()).toBe(false)
      await expect(backend.retrieve('my-secret')).resolves.toBe(prior)
    })

    it.each(['legacy\nname', 'legacy\rname'])('replaces an existing legacy ID %j', async (id) => {
      const keychain = mockKeychain()
      keychain.seedLegacy(id, 'prior')
      await expect(backend.retrieve(id)).resolves.toBe('prior')

      await backend.store(id, 'replacement')
      await expect(backend.retrieve(id)).resolves.toBe('replacement')
      expect(mockExecCommandFull.mock.calls.some(([, args]) => args[0] === '-i')).toBe(false)
    })

    it('replaces an existing legacy ID larger than the interactive create limit', async () => {
      const id = 'a'.repeat(4096)
      const keychain = mockKeychain()
      keychain.seedLegacy(id, 'prior')
      await expect(backend.retrieve(id)).resolves.toBe('prior')

      await backend.store(id, 'replacement')
      await expect(backend.retrieve(id)).resolves.toBe('replacement')
      expect(mockExecCommandFull.mock.calls.some(([, args]) => args[0] === '-i')).toBe(false)
    })

    it('returns only the successful replacement and keeps the write off argv', async () => {
      mockKeychain()
      await backend.store('my-secret', 'prior')
      const replacement = 'replacement-🔐\nvalue'
      await backend.store('my-secret', replacement)
      await expect(backend.retrieve('my-secret')).resolves.toBe(replacement)
      expect(mockExecCommand).not.toHaveBeenCalled()
      expect(mockExecCommandFull.mock.calls.map(([, args]) => args[0])).toEqual([
        'find-generic-password',
        '-l',
        '-i',
        'find-generic-password',
        '-l',
        'find-generic-password',
      ])
      const encoded = Buffer.from(replacement).toString('base64')
      expect(mockExecCommandFull).toHaveBeenNthCalledWith(
        5,
        '/usr/bin/osascript',
        [
          '-l',
          'JavaScript',
          '-e',
          KEYCHAIN_UPDATE_SCRIPT,
          '--',
          '/test/team clés.keychain-db',
          'vaultkeeper:my-secret',
          'vaultkeeper',
          String(encoded.length),
        ],
        { stdin: encoded },
      )
    })

    it('replaces an existing credential larger than the interactive create limit', async () => {
      mockKeychain()
      await backend.store('my-secret', 'prior')
      const replacement = '🔐'.repeat(1024)

      await backend.store('my-secret', replacement)
      await expect(backend.retrieve('my-secret')).resolves.toBe(replacement)
    })

    it('preserves the winning credential when two creates see an empty keychain', async () => {
      mockKeychain()
      const first = backend.store('my-secret', 'winner')
      const second = backend.store('my-secret', 'duplicate')
      await Promise.all([
        expect(first).resolves.toBeUndefined(),
        expect(second).rejects.toThrow(ExecError),
      ])
      await expect(backend.retrieve('my-secret')).resolves.toBe('winner')
    })

    it('stops if security could not initialize the lookup', async () => {
      mockExecCommandFull.mockResolvedValueOnce(
        makeResult(44, '', 'security: SecKeychainSearchCreateFromAttributes: failed'),
      )
      await expect(backend.store('my-secret', 'value')).rejects.toThrow(ExecError)
      expect(mockExecCommandFull).toHaveBeenCalledTimes(1)
    })

    it('quotes service names and writes an explicit empty password', async () => {
      mockExecCommandFull
        .mockResolvedValueOnce(makeResult(44))
        .mockResolvedValueOnce(makeResult(0, 'absent\n'))
        .mockResolvedValueOnce(makeResult(0))
      await backend.store('id "with quotes" and \\', '')
      expect(mockExecCommandFull).toHaveBeenLastCalledWith('security', ['-i'], {
        stdin:
          'add-generic-password -a "vaultkeeper" -s "vaultkeeper:id \\"with quotes\\" and \\\\" -w ""\n',
      })
    })

    it.each(['split\nline', 'carriage\rreturn'])(
      'rejects creation of a multiline ID %j',
      async (id) => {
        mockExecCommandFull.mockResolvedValueOnce(makeResult(44))
        await expect(backend.store(id, 'value')).rejects.toThrow(/creation.*without line breaks/)
        expect(mockExecCommandFull).toHaveBeenCalledExactlyOnceWith('security', [
          'find-generic-password',
          '-a',
          'vaultkeeper',
          '-s',
          `vaultkeeper:${id}`,
        ])
      },
    )

    it('rejects NUL before passing the ID to a subprocess', async () => {
      await expect(backend.store('embedded\0nul', 'value')).rejects.toThrow(ExecError)
      expect(mockExecCommandFull).not.toHaveBeenCalled()
    })

    it('rejects creation with oversized service metadata before writing', async () => {
      mockExecCommandFull.mockResolvedValueOnce(makeResult(44))
      await expect(backend.store('a'.repeat(300_000), 'value')).rejects.toThrow(/line limit/i)
      expect(mockExecCommandFull).toHaveBeenCalledExactlyOnceWith('security', [
        'find-generic-password',
        '-a',
        'vaultkeeper',
        '-s',
        `vaultkeeper:${'a'.repeat(300_000)}`,
      ])
    })

    it('rejects an oversized creation after lookup and before writing', async () => {
      mockExecCommandFull.mockResolvedValueOnce(makeResult(44))
      await expect(backend.store('my-secret', '🔐'.repeat(1024))).rejects.toThrow(/line limit/i)
      expect(mockExecCommandFull).toHaveBeenCalledExactlyOnceWith('security', [
        'find-generic-password',
        '-a',
        'vaultkeeper',
        '-s',
        'vaultkeeper:my-secret',
      ])
    })

    it('rejects a command enlarged by escaping before the write', async () => {
      mockExecCommandFull.mockResolvedValueOnce(makeResult(44))
      await expect(backend.store('"'.repeat(2048), '')).rejects.toThrow(/line limit/i)
      expect(mockExecCommandFull).toHaveBeenCalledTimes(1)
    })

    it('stops if the owning keychain cannot be identified safely', async () => {
      mockExecCommandFull.mockResolvedValueOnce(makeResult(0, 'unexpected metadata'))
      await expect(backend.store('my-secret', 'replacement')).rejects.toThrow(ExecError)
      expect(mockExecCommandFull).toHaveBeenCalledTimes(1)
    })

    it('reports a native failure even if the status wrapped to exit zero', async () => {
      mockExecCommandFull
        .mockResolvedValueOnce(makeResult(44))
        .mockResolvedValueOnce(makeResult(0, 'absent\n'))
        .mockResolvedValueOnce(makeResult(0, '', 'add-generic-password: returned -25600\n'))
      await expect(backend.store('my-secret', 'value')).rejects.toThrow(/write failed/)
    })

    it('omits credential-bearing diagnostics from errors', async () => {
      const secret = 'fake-sensitive-value'
      const encoded = Buffer.from(secret).toString('base64')
      mockExecCommandFull
        .mockResolvedValueOnce(makeResult(44))
        .mockResolvedValueOnce(makeResult(0, 'absent\n'))
        .mockResolvedValueOnce(makeResult(1, '', `${secret} ${encoded}`))
      const pending = backend.store('my-secret', secret)
      await expect(pending).rejects.toThrow(/write failed/)
      await expect(pending).rejects.not.toThrow(secret)
      await expect(pending).rejects.not.toThrow(encoded)
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
      const dumpOutput = ['class: "genp"', '    0x00000007 <blob>="some-other-service"'].join('\n')
      mockExecCommandFull.mockResolvedValue(makeResult(0, dumpOutput))

      const result = await backend.list()
      expect(result).toEqual([])
    })
  })
})
