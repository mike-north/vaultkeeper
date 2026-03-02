/**
 * Tests for 1Password backend discovery (SDK-based vault enumeration).
 *
 * @see https://developer.1password.com/docs/sdks/
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import type { VaultOverview } from '@1password/sdk'

// vi.hoisted ensures these declarations are available inside the vi.mock factory,
// which is hoisted to the top of the file before any imports run.
const { mockVaultsList, mockCreateClient } = vi.hoisted(() => {
  const mockVaultsList = vi.fn<() => Promise<VaultOverview[]>>()
  const mockCreateClient = vi.fn().mockResolvedValue({ vaults: { list: mockVaultsList } })
  return { mockVaultsList, mockCreateClient }
})

vi.mock('@1password/sdk', () => ({
  createClient: mockCreateClient,
  DesktopAuth: vi.fn().mockImplementation((accountName: string) => ({ accountName })),
}))

import { createOnePasswordSetup } from '../../../../src/backend/discovery/one-password.js'
import { SetupError } from '../../../../src/errors.js'

/** Builds a minimal VaultOverview for testing. */
function makeVaultOverview(id: string, title: string): VaultOverview {
  return {
    id,
    title,
    description: '',
    vaultType: 'EVERYONE',
    activeItemCount: 0,
    contentVersion: 1,
    attributeVersion: 1,
    createdAt: new Date('2024-01-01T00:00:00.000Z'),
    updatedAt: new Date('2024-01-01T00:00:00.000Z'),
  }
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

/** Extracts the `key` string from a yielded setup question (typed as unknown). */
function questionKey(q: unknown): string {
  if (typeof q === 'object' && q !== null && 'key' in q && typeof q.key === 'string') {
    return q.key
  }
  throw new TypeError(`Expected a SetupQuestion, got: ${String(q)}`)
}

beforeEach(() => {
  // clearAllMocks resets call counts/results but preserves implementations set via
  // mockResolvedValue in the factory above. This keeps the default createClient →
  // { vaults: { list: mockVaultsList } } resolution in effect between tests.
  vi.clearAllMocks()
})

// ---------------------------------------------------------------------------
// createOnePasswordSetup — account name question
// ---------------------------------------------------------------------------

describe('createOnePasswordSetup', () => {
  describe('account name question', () => {
    it('first yields a free-form question asking for the account name', async () => {
      mockVaultsList.mockResolvedValue([makeVaultOverview('v1', 'Personal')])

      const gen = createOnePasswordSetup()
      const first = await gen.next()

      expect(first.done).toBe(false)
      expect(first.value).toMatchObject({
        key: 'account',
        prompt: 'Enter your 1Password account name',
      })
    })

    it('account name question has no choices (free-form input)', async () => {
      mockVaultsList.mockResolvedValue([makeVaultOverview('v1', 'Personal')])

      const gen = createOnePasswordSetup()
      const first = await gen.next()

      expect(first.done).toBe(false)
      expect(first.value).not.toHaveProperty('choices')
    })
  })

  // -------------------------------------------------------------------------
  // Single vault auto-selection
  // -------------------------------------------------------------------------

  describe('single vault auto-selection', () => {
    it('auto-selects single vault without yielding a vault question', async () => {
      mockVaultsList.mockResolvedValue([makeVaultOverview('vault-1', 'Personal')])

      const gen = createOnePasswordSetup()
      const { yielded, returned } = await driveGenerator(gen, ['my-account', 'session'])

      expect(yielded.map(questionKey)).not.toContain('vault')
      expect(returned).toMatchObject({ options: { vault: 'vault-1' } })
    })

    it('includes the account name and access mode in the result', async () => {
      mockVaultsList.mockResolvedValue([makeVaultOverview('vault-1', 'Personal')])

      const gen = createOnePasswordSetup()
      const { returned } = await driveGenerator(gen, ['acme-corp', 'per-access'])

      expect(returned).toEqual({
        options: { account: 'acme-corp', vault: 'vault-1', accessMode: 'per-access' },
      })
    })
  })

  // -------------------------------------------------------------------------
  // Multiple vault selection
  // -------------------------------------------------------------------------

  describe('multiple vaults', () => {
    it('yields a vault question when multiple vaults exist', async () => {
      mockVaultsList.mockResolvedValue([
        makeVaultOverview('vault-1', 'Personal'),
        makeVaultOverview('vault-2', 'Work'),
      ])

      const gen = createOnePasswordSetup()
      const { yielded } = await driveGenerator(gen, ['my-account', 'vault-2', 'session'])

      expect(yielded.map(questionKey)).toContain('vault')
    })

    it('vault question choices map vault id to title', async () => {
      mockVaultsList.mockResolvedValue([
        makeVaultOverview('vault-1', 'Personal'),
        makeVaultOverview('vault-2', 'Work'),
      ])

      const gen = createOnePasswordSetup()
      // Consume account question
      await gen.next()
      // Feed account name — next yield is vault question (multiple vaults)
      const vaultResult = await gen.next('my-account')

      expect(vaultResult.done).toBe(false)
      expect(vaultResult.value).toMatchObject({
        key: 'vault',
        prompt: 'Select a vault',
        choices: [
          { value: 'vault-1', label: 'Personal' },
          { value: 'vault-2', label: 'Work' },
        ],
      })
    })

    it('uses the selected vault id in the result', async () => {
      mockVaultsList.mockResolvedValue([
        makeVaultOverview('vault-1', 'Personal'),
        makeVaultOverview('vault-2', 'Work'),
      ])

      const gen = createOnePasswordSetup()
      const { returned } = await driveGenerator(gen, ['my-account', 'vault-2', 'session'])

      expect(returned).toMatchObject({ options: { vault: 'vault-2' } })
    })
  })

  // -------------------------------------------------------------------------
  // Access mode question
  // -------------------------------------------------------------------------

  describe('access mode question', () => {
    it('always yields an access mode question', async () => {
      mockVaultsList.mockResolvedValue([makeVaultOverview('vault-1', 'Personal')])

      const gen = createOnePasswordSetup()
      const { yielded } = await driveGenerator(gen, ['my-account', 'session'])

      expect(yielded.map(questionKey)).toContain('accessMode')
    })

    it('access mode question has session and per-access choices', async () => {
      mockVaultsList.mockResolvedValue([makeVaultOverview('vault-1', 'Personal')])

      const gen = createOnePasswordSetup()
      // Consume account question
      await gen.next()
      // Feed account name — next yield is access mode question (single vault → no vault question)
      const accessModeResult = await gen.next('my-account')

      expect(accessModeResult.done).toBe(false)
      expect(accessModeResult.value).toMatchObject({
        key: 'accessMode',
        prompt: 'How should secrets be accessed?',
        choices: [
          { value: 'session', label: 'Session (one prompt per session)' },
          { value: 'per-access', label: 'Per-access (prompt for every retrieval)' },
        ],
      })
    })

    it('records session access mode in result', async () => {
      mockVaultsList.mockResolvedValue([makeVaultOverview('vault-1', 'Personal')])

      const gen = createOnePasswordSetup()
      const { returned } = await driveGenerator(gen, ['my-account', 'session'])

      expect(returned).toMatchObject({ options: { accessMode: 'session' } })
    })

    it('records per-access access mode in result', async () => {
      mockVaultsList.mockResolvedValue([makeVaultOverview('vault-1', 'Personal')])

      const gen = createOnePasswordSetup()
      const { returned } = await driveGenerator(gen, ['my-account', 'per-access'])

      expect(returned).toMatchObject({ options: { accessMode: 'per-access' } })
    })
  })

  // -------------------------------------------------------------------------
  // Error cases
  // -------------------------------------------------------------------------

  describe('error cases', () => {
    it('throws SetupError when account name is empty', async () => {
      const gen = createOnePasswordSetup()
      await expect(driveGenerator(gen, ['', 'session'])).rejects.toBeInstanceOf(SetupError)
    })

    it('throws SetupError when account name is whitespace-only', async () => {
      const gen = createOnePasswordSetup()
      await expect(driveGenerator(gen, ['   ', 'session'])).rejects.toBeInstanceOf(SetupError)
    })

    it('throws SetupError when SDK client creation fails', async () => {
      mockCreateClient.mockRejectedValueOnce(new Error('biometric auth failed'))

      const gen = createOnePasswordSetup()
      await expect(driveGenerator(gen, ['my-account', 'session'])).rejects.toBeInstanceOf(SetupError)
    })

    it('SetupError for client creation failure has dependency "1Password SDK"', async () => {
      mockCreateClient.mockRejectedValueOnce(new Error('biometric auth failed'))

      const gen = createOnePasswordSetup()
      await expect(driveGenerator(gen, ['my-account', 'session'])).rejects.toMatchObject({
        dependency: '1Password SDK',
      })
    })

    it('SetupError for client creation includes underlying error detail', async () => {
      mockCreateClient.mockRejectedValueOnce(new Error('biometric auth failed'))

      const gen = createOnePasswordSetup()
      await expect(driveGenerator(gen, ['my-account', 'session'])).rejects.toThrow('biometric auth failed')
    })

    it('throws SetupError when vault listing fails', async () => {
      mockVaultsList.mockRejectedValueOnce(new Error('network timeout'))

      const gen = createOnePasswordSetup()
      await expect(driveGenerator(gen, ['my-account', 'session'])).rejects.toBeInstanceOf(SetupError)
    })

    it('SetupError for vault listing failure has dependency "1Password SDK"', async () => {
      mockVaultsList.mockRejectedValueOnce(new Error('network timeout'))

      const gen = createOnePasswordSetup()
      await expect(driveGenerator(gen, ['my-account', 'session'])).rejects.toMatchObject({
        dependency: '1Password SDK',
      })
    })

    it('SetupError for vault listing failure includes underlying error detail', async () => {
      mockVaultsList.mockRejectedValueOnce(new Error('network timeout'))

      const gen = createOnePasswordSetup()
      await expect(driveGenerator(gen, ['my-account', 'session'])).rejects.toThrow('network timeout')
    })

    it('throws SetupError when no vaults are found', async () => {
      mockVaultsList.mockResolvedValueOnce([])

      const gen = createOnePasswordSetup()
      await expect(driveGenerator(gen, ['my-account', 'session'])).rejects.toBeInstanceOf(SetupError)
    })

    it('SetupError for no vaults has dependency "1Password SDK"', async () => {
      mockVaultsList.mockResolvedValueOnce([])

      const gen = createOnePasswordSetup()
      await expect(driveGenerator(gen, ['my-account', 'session'])).rejects.toMatchObject({
        dependency: '1Password SDK',
      })
    })

    it('SetupError for no vaults references the account name', async () => {
      mockVaultsList.mockResolvedValueOnce([])

      const gen = createOnePasswordSetup()
      await expect(driveGenerator(gen, ['acme-corp', 'session'])).rejects.toThrow('acme-corp')
    })
  })
})
