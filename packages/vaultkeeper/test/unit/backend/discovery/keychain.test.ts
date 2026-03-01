/**
 * Tests for macOS Keychain backend discovery.
 *
 * @see https://ss64.com/mac/security.html — `security list-keychains`
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'

vi.mock('../../../../src/util/exec.js', () => ({
  execCommand: vi.fn(),
  execCommandFull: vi.fn(),
}))

import { execCommand } from '../../../../src/util/exec.js'
import { listKeychains, createKeychainSetup } from '../../../../src/backend/discovery/keychain.js'
import { SetupError } from '../../../../src/errors.js'
import type { SetupQuestion } from '../../../../src/backend/setup-types.js'

const mockExecCommand = vi.mocked(execCommand)

/** Two-keychain output as produced by `security list-keychains` on macOS. */
const TWO_KEYCHAINS_OUTPUT =
  '    "/Users/testuser/Library/Keychains/login.keychain-db"\n    "/Library/Keychains/System.keychain"'

/** Single-keychain output. */
const ONE_KEYCHAIN_OUTPUT = '    "/Users/testuser/Library/Keychains/login.keychain-db"'

describe('listKeychains', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('parses a single quoted path and derives its display name', async () => {
    mockExecCommand.mockResolvedValue(ONE_KEYCHAIN_OUTPUT)

    const result = await listKeychains()

    expect(result).toHaveLength(1)
    expect(result[0]).toEqual({
      value: '/Users/testuser/Library/Keychains/login.keychain-db',
      label: 'login',
    })
  })

  it('parses multiple quoted paths and derives display names for each', async () => {
    mockExecCommand.mockResolvedValue(TWO_KEYCHAINS_OUTPUT)

    const result = await listKeychains()

    expect(result).toHaveLength(2)
    expect(result[0]).toEqual({
      value: '/Users/testuser/Library/Keychains/login.keychain-db',
      label: 'login',
    })
    expect(result[1]).toEqual({
      value: '/Library/Keychains/System.keychain',
      label: 'System',
    })
  })

  it('returns an empty array when output is empty', async () => {
    mockExecCommand.mockResolvedValue('')

    const result = await listKeychains()

    expect(result).toEqual([])
  })

  it('calls security list-keychains with no extra arguments', async () => {
    mockExecCommand.mockResolvedValue(ONE_KEYCHAIN_OUTPUT)

    await listKeychains()

    expect(mockExecCommand).toHaveBeenCalledWith('security', ['list-keychains'])
  })

  it('skips lines that are not quoted paths', async () => {
    // Output containing a blank line and a non-quoted line (defensive case)
    mockExecCommand.mockResolvedValue(
      '\n    "/Library/Keychains/System.keychain"\n    not-a-path\n',
    )

    const result = await listKeychains()

    expect(result).toHaveLength(1)
    expect(result[0]?.value).toBe('/Library/Keychains/System.keychain')
  })
})

describe('createKeychainSetup', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('auto-selects the only keychain and returns without yielding when exactly one exists', async () => {
    mockExecCommand.mockResolvedValue(ONE_KEYCHAIN_OUTPUT)

    const gen = createKeychainSetup()
    const result = await gen.next()

    expect(result.done).toBe(true)
    expect(result.value).toEqual({
      options: { keychain: '/Users/testuser/Library/Keychains/login.keychain-db' },
    })
  })

  it('yields a keychain selection question when multiple keychains exist', async () => {
    mockExecCommand.mockResolvedValue(TWO_KEYCHAINS_OUTPUT)

    const gen = createKeychainSetup()
    const first = await gen.next()

    expect(first.done).toBe(false)

    // Narrow via type guard so we can access SetupQuestion properties without a cast.
    if (first.done !== false) throw new Error('Expected generator to yield a question')
    const question: SetupQuestion = first.value
    expect(question.key).toBe('keychain')
    expect(question.prompt).toBe('Select a keychain')
    expect(question.choices).toEqual([
      { value: '/Users/testuser/Library/Keychains/login.keychain-db', label: 'login' },
      { value: '/Library/Keychains/System.keychain', label: 'System' },
    ])
  })

  it('returns the caller-supplied keychain path after the selection question', async () => {
    mockExecCommand.mockResolvedValue(TWO_KEYCHAINS_OUTPUT)

    const gen = createKeychainSetup()

    // Receive the question
    await gen.next()

    // Send back the chosen path
    const result = await gen.next('/Library/Keychains/System.keychain')

    expect(result.done).toBe(true)
    expect(result.value).toEqual({
      options: { keychain: '/Library/Keychains/System.keychain' },
    })
  })

  it('throws SetupError when no keychains are found', async () => {
    mockExecCommand.mockResolvedValue('')

    const gen = createKeychainSetup()

    await expect(gen.next()).rejects.toBeInstanceOf(SetupError)
  })

  it('thrown SetupError has dependency set to macOS Keychain', async () => {
    mockExecCommand.mockResolvedValue('')

    const gen = createKeychainSetup()

    await expect(gen.next()).rejects.toSatisfy(
      (err): err is SetupError =>
        err instanceof SetupError && err.dependency === 'macOS Keychain',
    )
  })

  it('propagates errors thrown by execCommand', async () => {
    mockExecCommand.mockRejectedValue(new Error('security tool not found'))

    const gen = createKeychainSetup()

    await expect(gen.next()).rejects.toThrow('security tool not found')
  })
})
