/**
 * Tests for 1Password backend discovery (account and vault enumeration).
 *
 * @see https://developer.1password.com/docs/cli/reference/management-commands/account/
 * @see https://developer.1password.com/docs/cli/reference/management-commands/vault/
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'

vi.mock('../../../../src/util/exec.js', () => ({
  execCommand: vi.fn(),
  execCommandFull: vi.fn(),
}))

import { execCommand } from '../../../../src/util/exec.js'
import {
  listAccounts,
  listVaults,
  createOnePasswordSetup,
} from '../../../../src/backend/discovery/one-password.js'
import { SetupError } from '../../../../src/errors.js'

const mockExecCommand = vi.mocked(execCommand)

/** Builds a JSON string for `op account list` output. */
function makeAccountListJson(
  entries: { account_uuid: string; url: string; email: string }[],
): string {
  return JSON.stringify(entries)
}

/** Builds a JSON string for `op account get` output (single object, not array). */
function makeAccountGetJson(entry: { name: string }): string {
  return JSON.stringify(entry)
}

/** Builds a JSON string for `op vault list` output. */
function makeVaultListJson(entries: { id: string; name: string }[]): string {
  return JSON.stringify(entries)
}

/** Drives an AsyncGenerator to completion, collecting yielded values and feeding answers. */
async function driveGenerator(
  gen: AsyncGenerator<unknown, unknown, string>,
  answers: string[],
): Promise<{ yielded: unknown[]; returned: unknown }> {
  const yielded: unknown[] = []
  let result = await gen.next()

  for (const answer of answers) {
    if (result.done === true) break
    yielded.push(result.value)
    result = await gen.next(answer)
  }

  // If the generator is still running after all answers are consumed, collect remaining yields
  while (result.done !== true) {
    yielded.push(result.value)
    result = await gen.next('')
  }

  return { yielded, returned: result.value }
}

beforeEach(() => {
  vi.clearAllMocks()
  // Suppress retry delays in tests by removing setTimeout delays
  vi.useFakeTimers()
})

afterEach(() => {
  vi.useRealTimers()
})

// ---------------------------------------------------------------------------
// listAccounts
// ---------------------------------------------------------------------------

describe('listAccounts', () => {
  it('returns a SetupChoice per account with "name (email)" label', async () => {
    mockExecCommand
      .mockResolvedValueOnce(
        makeAccountListJson([
          { account_uuid: 'uuid-1', url: 'https://my.1password.com', email: 'alice@example.com' },
        ]),
      )
      .mockResolvedValueOnce(makeAccountGetJson({ name: 'Alice Corp' }))

    const promise = listAccounts()
    await vi.runAllTimersAsync()
    const choices = await promise

    expect(choices).toHaveLength(1)
    expect(choices[0]).toEqual({ value: 'uuid-1', label: 'Alice Corp (alice@example.com)' })
  })

  it('returns multiple choices for multiple accounts', async () => {
    mockExecCommand
      .mockResolvedValueOnce(
        makeAccountListJson([
          { account_uuid: 'uuid-1', url: 'https://a.1password.com', email: 'alice@example.com' },
          { account_uuid: 'uuid-2', url: 'https://b.1password.com', email: 'bob@example.com' },
        ]),
      )
      // account get for uuid-1
      .mockResolvedValueOnce(makeAccountGetJson({ name: 'Alice Corp' }))
      // account get for uuid-2
      .mockResolvedValueOnce(makeAccountGetJson({ name: 'Bob Inc' }))

    const promise = listAccounts()
    await vi.runAllTimersAsync()
    const choices = await promise

    expect(choices).toHaveLength(2)
    expect(choices[0]).toEqual({ value: 'uuid-1', label: 'Alice Corp (alice@example.com)' })
    expect(choices[1]).toEqual({ value: 'uuid-2', label: 'Bob Inc (bob@example.com)' })
  })

  it('returns empty array when op account list fails', async () => {
    mockExecCommand.mockRejectedValue(new Error('command not found: op'))

    const promise = listAccounts()
    await vi.runAllTimersAsync()
    const choices = await promise

    expect(choices).toHaveLength(0)
  })

  it('returns empty array when op account list returns empty JSON array', async () => {
    mockExecCommand.mockResolvedValueOnce('[]')

    const promise = listAccounts()
    await vi.runAllTimersAsync()
    const choices = await promise

    expect(choices).toHaveLength(0)
  })

  it('falls back to email-only label when op account get fails', async () => {
    mockExecCommand
      .mockResolvedValueOnce(
        makeAccountListJson([
          { account_uuid: 'uuid-1', url: 'https://a.1password.com', email: 'alice@example.com' },
        ]),
      )
      // op account get fails (after retries)
      .mockRejectedValue(new Error('account get failed'))

    const promise = listAccounts()
    await vi.runAllTimersAsync()
    const choices = await promise

    expect(choices).toHaveLength(1)
    expect(choices[0]).toEqual({ value: 'uuid-1', label: 'alice@example.com' })
  })

  describe('retry behavior', () => {
    it('retries up to 2 times on failure before returning empty array', async () => {
      // All attempts fail (initial + 2 retries = 3 calls total)
      mockExecCommand.mockRejectedValue(new Error('transient failure'))

      const promise = listAccounts()
      await vi.runAllTimersAsync()
      await promise

      // execCommand called 3 times: attempt 0, retry 1, retry 2
      expect(mockExecCommand).toHaveBeenCalledTimes(3)
    })

    it('succeeds on a retry after an initial failure', async () => {
      mockExecCommand
        .mockRejectedValueOnce(new Error('transient'))
        .mockResolvedValueOnce(
          makeAccountListJson([
            { account_uuid: 'uuid-1', url: 'https://a.1password.com', email: 'alice@example.com' },
          ]),
        )
        .mockResolvedValueOnce(makeAccountGetJson({ name: 'Alice' }))

      const promise = listAccounts()
      await vi.runAllTimersAsync()
      const choices = await promise

      expect(choices).toHaveLength(1)
      // First call failed (list attempt 1), second call succeeded (list attempt 2)
      expect(mockExecCommand).toHaveBeenCalledTimes(3)
    })
  })
})

// ---------------------------------------------------------------------------
// listVaults
// ---------------------------------------------------------------------------

describe('listVaults', () => {
  it('returns a SetupChoice per vault', async () => {
    mockExecCommand.mockResolvedValueOnce(
      makeVaultListJson([
        { id: 'vault-id-1', name: 'Personal' },
        { id: 'vault-id-2', name: 'Work' },
      ]),
    )

    const choices = await listVaults('uuid-1')

    expect(choices).toHaveLength(2)
    expect(choices[0]).toEqual({ value: 'vault-id-1', label: 'Personal' })
    expect(choices[1]).toEqual({ value: 'vault-id-2', label: 'Work' })
  })

  it('passes the account UUID to op vault list', async () => {
    mockExecCommand.mockResolvedValueOnce(makeVaultListJson([{ id: 'v1', name: 'Vault' }]))

    await listVaults('my-account-uuid')

    expect(mockExecCommand).toHaveBeenCalledWith('op', [
      'vault',
      'list',
      '--account',
      'my-account-uuid',
      '--format=json',
    ])
  })

  it('throws when op vault list fails', async () => {
    mockExecCommand.mockRejectedValue(new Error('op not found'))

    await expect(listVaults('uuid-1')).rejects.toThrow('op not found')
  })

  it('returns empty array when JSON is an empty array', async () => {
    mockExecCommand.mockResolvedValueOnce('[]')

    const choices = await listVaults('uuid-1')

    expect(choices).toHaveLength(0)
  })
})

// ---------------------------------------------------------------------------
// createOnePasswordSetup
// ---------------------------------------------------------------------------

describe('createOnePasswordSetup', () => {
  it('auto-selects single account and single vault without yielding questions', async () => {
    // account list
    mockExecCommand
      .mockResolvedValueOnce(
        makeAccountListJson([
          { account_uuid: 'uuid-1', url: 'https://a.1password.com', email: 'alice@example.com' },
        ]),
      )
      // account get
      .mockResolvedValueOnce(makeAccountGetJson({ name: 'Alice' }))
      // vault list
      .mockResolvedValueOnce(makeVaultListJson([{ id: 'vault-1', name: 'Personal' }]))

    const gen = createOnePasswordSetup()
    const promise = driveGenerator(gen, [])
    await vi.runAllTimersAsync()
    const { yielded, returned } = await promise

    expect(yielded).toHaveLength(0)
    expect(returned).toEqual({ options: { account: 'uuid-1', vault: 'vault-1' } })
  })

  it('yields account question when multiple accounts exist', async () => {
    mockExecCommand
      .mockResolvedValueOnce(
        makeAccountListJson([
          { account_uuid: 'uuid-1', url: 'https://a.1password.com', email: 'alice@example.com' },
          { account_uuid: 'uuid-2', url: 'https://b.1password.com', email: 'bob@example.com' },
        ]),
      )
      .mockResolvedValueOnce(makeAccountGetJson({ name: 'Alice' }))
      .mockResolvedValueOnce(makeAccountGetJson({ name: 'Bob' }))
      // vault list for selected account (uuid-1 sent as answer)
      .mockResolvedValueOnce(makeVaultListJson([{ id: 'vault-1', name: 'Personal' }]))

    const gen = createOnePasswordSetup()
    const promise = driveGenerator(gen, ['uuid-1'])
    await vi.runAllTimersAsync()
    const { yielded, returned } = await promise

    expect(yielded).toHaveLength(1)
    const accountQuestion = yielded[0]
    expect(accountQuestion).toMatchObject({
      key: 'account',
      prompt: 'Select a 1Password account',
    })
    expect(returned).toEqual({ options: { account: 'uuid-1', vault: 'vault-1' } })
  })

  it('yields account question then vault question when multiple of both exist', async () => {
    mockExecCommand
      .mockResolvedValueOnce(
        makeAccountListJson([
          { account_uuid: 'uuid-1', url: 'https://a.1password.com', email: 'alice@example.com' },
          { account_uuid: 'uuid-2', url: 'https://b.1password.com', email: 'bob@example.com' },
        ]),
      )
      .mockResolvedValueOnce(makeAccountGetJson({ name: 'Alice' }))
      .mockResolvedValueOnce(makeAccountGetJson({ name: 'Bob' }))
      .mockResolvedValueOnce(
        makeVaultListJson([
          { id: 'vault-1', name: 'Personal' },
          { id: 'vault-2', name: 'Work' },
        ]),
      )

    const gen = createOnePasswordSetup()
    const promise = driveGenerator(gen, ['uuid-2', 'vault-2'])
    await vi.runAllTimersAsync()
    const { yielded, returned } = await promise

    expect(yielded).toHaveLength(2)
    expect(yielded[0]).toMatchObject({ key: 'account' })
    expect(yielded[1]).toMatchObject({ key: 'vault', prompt: 'Select a vault' })
    expect(returned).toEqual({ options: { account: 'uuid-2', vault: 'vault-2' } })
  })

  it('yields account question only when multiple accounts but single vault', async () => {
    mockExecCommand
      .mockResolvedValueOnce(
        makeAccountListJson([
          { account_uuid: 'uuid-1', url: 'https://a.1password.com', email: 'alice@example.com' },
          { account_uuid: 'uuid-2', url: 'https://b.1password.com', email: 'bob@example.com' },
        ]),
      )
      .mockResolvedValueOnce(makeAccountGetJson({ name: 'Alice' }))
      .mockResolvedValueOnce(makeAccountGetJson({ name: 'Bob' }))
      .mockResolvedValueOnce(makeVaultListJson([{ id: 'vault-1', name: 'Personal' }]))

    const gen = createOnePasswordSetup()
    const promise = driveGenerator(gen, ['uuid-1'])
    await vi.runAllTimersAsync()
    const { yielded, returned } = await promise

    expect(yielded).toHaveLength(1)
    expect(yielded[0]).toMatchObject({ key: 'account' })
    expect(returned).toEqual({ options: { account: 'uuid-1', vault: 'vault-1' } })
  })

  it('throws SetupError when no accounts are found', async () => {
    mockExecCommand.mockRejectedValue(new Error('command not found: op'))

    const gen = createOnePasswordSetup()
    // Attach rejects handler before advancing timers to prevent unhandled rejection
    const assertion = expect(driveGenerator(gen, [])).rejects.toBeInstanceOf(SetupError)
    await vi.runAllTimersAsync()
    await assertion
  })

  it('thrown SetupError for no accounts has dependency set', async () => {
    mockExecCommand.mockRejectedValue(new Error('command not found: op'))

    const gen = createOnePasswordSetup()
    const assertion = expect(driveGenerator(gen, [])).rejects.toMatchObject({
      dependency: '1Password CLI (op)',
    })
    await vi.runAllTimersAsync()
    await assertion
  })

  it('throws SetupError when no vaults are found for the selected account', async () => {
    mockExecCommand
      .mockResolvedValueOnce(
        makeAccountListJson([
          { account_uuid: 'uuid-1', url: 'https://a.1password.com', email: 'alice@example.com' },
        ]),
      )
      .mockResolvedValueOnce(makeAccountGetJson({ name: 'Alice' }))
      // vault list returns empty
      .mockResolvedValueOnce('[]')

    const gen = createOnePasswordSetup()
    const assertion = expect(driveGenerator(gen, [])).rejects.toBeInstanceOf(SetupError)
    await vi.runAllTimersAsync()
    await assertion
  })

  it('throws SetupError with CLI dependency when op vault list fails', async () => {
    mockExecCommand
      .mockResolvedValueOnce(
        makeAccountListJson([
          { account_uuid: 'uuid-1', url: 'https://a.1password.com', email: 'alice@example.com' },
        ]),
      )
      .mockResolvedValueOnce(makeAccountGetJson({ name: 'Alice' }))
      // vault list command fails
      .mockRejectedValueOnce(new Error('op CLI not authenticated'))

    const gen = createOnePasswordSetup()
    const assertion = expect(driveGenerator(gen, [])).rejects.toThrow('Could not list vaults')
    await vi.runAllTimersAsync()
    await assertion
  })

  it('includes underlying error detail when op vault list fails', async () => {
    mockExecCommand
      .mockResolvedValueOnce(
        makeAccountListJson([
          { account_uuid: 'uuid-1', url: 'https://a.1password.com', email: 'alice@example.com' },
        ]),
      )
      .mockResolvedValueOnce(makeAccountGetJson({ name: 'Alice' }))
      .mockRejectedValueOnce(new Error('connect ECONNREFUSED'))

    const gen = createOnePasswordSetup()
    const assertion = expect(driveGenerator(gen, [])).rejects.toThrow('connect ECONNREFUSED')
    await vi.runAllTimersAsync()
    await assertion
  })

  it('thrown SetupError for op CLI failure has correct dependency', async () => {
    mockExecCommand
      .mockResolvedValueOnce(
        makeAccountListJson([
          { account_uuid: 'uuid-1', url: 'https://a.1password.com', email: 'alice@example.com' },
        ]),
      )
      .mockResolvedValueOnce(makeAccountGetJson({ name: 'Alice' }))
      // vault list command fails
      .mockRejectedValueOnce(new Error('op CLI not authenticated'))

    const gen = createOnePasswordSetup()
    const assertion = expect(driveGenerator(gen, [])).rejects.toHaveProperty('dependency', '1Password CLI (op)')
    await vi.runAllTimersAsync()
    await assertion
  })

  it('thrown SetupError for zero vaults has correct dependency', async () => {
    mockExecCommand
      .mockResolvedValueOnce(
        makeAccountListJson([
          { account_uuid: 'uuid-1', url: 'https://a.1password.com', email: 'alice@example.com' },
        ]),
      )
      .mockResolvedValueOnce(makeAccountGetJson({ name: 'Alice' }))
      .mockResolvedValueOnce('[]')

    const gen = createOnePasswordSetup()
    const assertion = expect(driveGenerator(gen, [])).rejects.toThrow('No vaults found')
    await vi.runAllTimersAsync()
    await assertion
  })

  it('thrown SetupError for zero vaults has correct dependency value', async () => {
    mockExecCommand
      .mockResolvedValueOnce(
        makeAccountListJson([
          { account_uuid: 'uuid-1', url: 'https://a.1password.com', email: 'alice@example.com' },
        ]),
      )
      .mockResolvedValueOnce(makeAccountGetJson({ name: 'Alice' }))
      .mockResolvedValueOnce('[]')

    const gen = createOnePasswordSetup()
    const assertion = expect(driveGenerator(gen, [])).rejects.toHaveProperty('dependency', '1Password CLI (op)')
    await vi.runAllTimersAsync()
    await assertion
  })

  it('account question choices contain value and label for each account', async () => {
    mockExecCommand
      .mockResolvedValueOnce(
        makeAccountListJson([
          { account_uuid: 'uuid-1', url: 'https://a.1password.com', email: 'alice@example.com' },
          { account_uuid: 'uuid-2', url: 'https://b.1password.com', email: 'bob@example.com' },
        ]),
      )
      .mockResolvedValueOnce(makeAccountGetJson({ name: 'Alice Corp' }))
      .mockResolvedValueOnce(makeAccountGetJson({ name: 'Bob Inc' }))
      .mockResolvedValueOnce(makeVaultListJson([{ id: 'vault-1', name: 'Personal' }]))

    const gen = createOnePasswordSetup()
    const firstResult = await gen.next()
    await vi.runAllTimersAsync()

    expect(firstResult.done).toBe(false)
    const question = firstResult.value
    expect(question).toMatchObject({
      choices: [
        { value: 'uuid-1', label: 'Alice Corp (alice@example.com)' },
        { value: 'uuid-2', label: 'Bob Inc (bob@example.com)' },
      ],
    })
  })
})
