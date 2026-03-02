/**
 * Tests for the 1Password SDK-based backend.
 *
 * @see https://developer.1password.com/docs/sdks/
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'

// ---- Hoist mock variables so factories can close over them ----

const {
  mockCreate,
  mockPut,
  mockDelete,
  mockList,
  mockGet,
  mockCreateClient,
  mockSpawn,
  MockDesktopAuth,
  MockDesktopSessionExpiredError,
  mockClient,
} = vi.hoisted(() => {
  const mockCreate = vi.fn()
  const mockPut = vi.fn()
  const mockDelete = vi.fn()
  const mockList = vi.fn()
  const mockGet = vi.fn()

  const mockItems = {
    create: mockCreate,
    put: mockPut,
    delete: mockDelete,
    list: mockList,
    get: mockGet,
  }

  const mockClient = { items: mockItems }

  const mockCreateClient = vi.fn().mockResolvedValue(mockClient)

  class MockDesktopAuth {
    accountName: string
    constructor(accountName: string) {
      this.accountName = accountName
    }
  }

  class MockDesktopSessionExpiredError extends Error {
    constructor(message: string) {
      super(message)
      this.name = 'DesktopSessionExpiredError'
    }
  }

  const mockSpawn = vi.fn()

  return {
    mockCreate,
    mockPut,
    mockDelete,
    mockList,
    mockGet,
    mockCreateClient,
    mockSpawn,
    MockDesktopAuth,
    MockDesktopSessionExpiredError,
    mockClient,
  }
})

// ---- Mock @1password/sdk ----

vi.mock('@1password/sdk', () => ({
  createClient: mockCreateClient,
  DesktopAuth: MockDesktopAuth,
  DesktopSessionExpiredError: MockDesktopSessionExpiredError,
  ItemCategory: {
    Password: 'Password',
  },
  ItemFieldType: {
    Concealed: 'Concealed',
  },
}))

// ---- Mock node:child_process for per-access mode tests ----

vi.mock('node:child_process', () => ({
  spawn: mockSpawn,
}))

// ---- Import backend under test (after mocks are set up) ----

import { OnePasswordBackend } from '../../../src/backend/one-password-backend.js'
import {
  SecretNotFoundError,
  PluginNotFoundError,
  BackendLockedError,
  AuthorizationDeniedError,
} from '../../../src/errors.js'

// ---- Test helpers ----

interface ItemOverviewLike {
  id: string
  title: string
  tags: string[]
  category: string
  vaultId: string
  websites: []
  createdAt: Date
  updatedAt: Date
  state: string
}

interface ItemFieldLike {
  id: string
  title: string
  fieldType: string
  value: string
}

interface ItemLike {
  id: string
  title: string
  category: string
  vaultId: string
  fields: ItemFieldLike[]
  sections: []
  notes: string
  tags: string[]
  websites: []
  version: number
  files: []
  createdAt: Date
  updatedAt: Date
}

const VAULT_ID = 'vault-abc123'
const ACCOUNT_NAME = 'my-account'
const FIXED_DATE = new Date('2024-01-15T10:30:00.000Z')

function makeOverview(
  id: string,
  title: string,
  tags: string[] = ['vaultkeeper'],
): ItemOverviewLike {
  return {
    id,
    title,
    tags,
    category: 'Password',
    vaultId: VAULT_ID,
    websites: [],
    createdAt: FIXED_DATE,
    updatedAt: FIXED_DATE,
    state: 'active',
  }
}

function makeItem(id: string, title: string, secretValue: string): ItemLike {
  return {
    id,
    title,
    category: 'Password',
    vaultId: VAULT_ID,
    fields: [
      {
        id: 'password',
        title: 'password',
        fieldType: 'Concealed',
        value: secretValue,
      },
    ],
    sections: [],
    notes: '',
    tags: ['vaultkeeper'],
    websites: [],
    version: 1,
    files: [],
    createdAt: FIXED_DATE,
    updatedAt: FIXED_DATE,
  }
}

function makeSessionBackend(account = ACCOUNT_NAME): OnePasswordBackend {
  return new OnePasswordBackend({ vault: VAULT_ID, account })
}

function makePerAccessBackend(account = ACCOUNT_NAME): OnePasswordBackend {
  return new OnePasswordBackend({ vault: VAULT_ID, account, accessMode: 'per-access' })
}

function makeServiceAccountBackend(token: string): OnePasswordBackend {
  return new OnePasswordBackend({ vault: VAULT_ID, serviceAccountToken: token })
}

/** Shape that satisfies what `retrieveViaWorker` reads from the child process. */
interface MockChildProcess {
  stdout: {
    on: (event: string, cb: (chunk: Buffer) => void) => void
  }
  on: (event: string, cb: (errOrNothing?: Error) => void) => void
}

/**
 * Set up a mock child process whose stdout emits `data` and then fires `close`.
 */
function makeWorkerProcess(stdoutData: string): MockChildProcess {
  const dataListeners: ((chunk: Buffer) => void)[] = []
  const closeListeners: ((errOrNothing?: Error) => void)[] = []

  const stdout = {
    on: vi.fn((event: string, cb: (chunk: Buffer) => void) => {
      if (event === 'data') dataListeners.push(cb)
    }),
  }

  const proc: MockChildProcess = {
    stdout,
    on: vi.fn((event: string, cb: (errOrNothing?: Error) => void) => {
      if (event === 'close') closeListeners.push(cb)
    }),
  }

  // Schedule emission after mock resolves
  setTimeout(() => {
    for (const listener of dataListeners) {
      listener(Buffer.from(stdoutData, 'utf8'))
    }
    for (const listener of closeListeners) {
      listener()
    }
  }, 0)

  return proc
}

function makeWorkerErrorProcess(spawnErr: Error): MockChildProcess {
  const errorListeners: ((errOrNothing?: Error) => void)[] = []

  const stdout = {
    on: vi.fn(),
  }

  const proc: MockChildProcess = {
    stdout,
    on: vi.fn((event: string, cb: (errOrNothing?: Error) => void) => {
      if (event === 'error') errorListeners.push(cb)
    }),
  }

  setTimeout(() => {
    for (const listener of errorListeners) {
      listener(spawnErr)
    }
  }, 0)

  return proc
}

// ---- Tests ----

describe('OnePasswordBackend', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockCreateClient.mockResolvedValue(mockClient)
    mockList.mockResolvedValue([])
    mockGet.mockResolvedValue(makeItem('item-1', 'my-secret', 'secret-value'))
    mockCreate.mockResolvedValue(makeItem('item-new', 'my-secret', 'secret-value'))
    mockPut.mockResolvedValue(makeItem('item-1', 'my-secret', 'updated-value'))
    mockDelete.mockResolvedValue(undefined)
  })

  // ---- constructor validation ----

  describe('constructor', () => {
    it('should throw when per-access mode is combined with serviceAccountToken', () => {
      expect(
        () =>
          new OnePasswordBackend({
            vault: VAULT_ID,
            serviceAccountToken: 'token',
            accessMode: 'per-access',
          }),
      ).toThrow('per-access mode requires desktop biometric authentication')
    })
  })

  // ---- isAvailable ----

  describe('isAvailable', () => {
    it('should return true when SDK loads successfully', async () => {
      const backend = makeSessionBackend()
      const result = await backend.isAvailable()
      expect(result).toBe(true)
    })
  })

  // ---- Client caching (session mode) ----

  describe('session mode — client caching', () => {
    it('should call createClient only once across multiple operations', async () => {
      const backend = makeSessionBackend()
      mockList.mockResolvedValue([makeOverview('item-1', 'secret-a')])

      await backend.exists('secret-a')
      await backend.exists('secret-a')
      await backend.list()

      expect(mockCreateClient).toHaveBeenCalledTimes(1)
    })

    it('should pass account name via DesktopAuth when account is set', async () => {
      const backend = makeSessionBackend('my-team-account')
      await backend.isAvailable()
      await backend.list() // triggers acquireClient

      expect(mockCreateClient).toHaveBeenCalledTimes(1)
      const callArg: unknown = mockCreateClient.mock.calls[0]?.[0]
      expect(callArg).toMatchObject({ integrationName: 'vaultkeeper' })
      // Verify auth is a DesktopAuth-like object with the right accountName
      expect(callArg).toMatchObject({ auth: { accountName: 'my-team-account' } })
    })

    it('should pass service account token as a string when configured', async () => {
      const backend = makeServiceAccountBackend('ops-token-xyz')
      await backend.list()

      expect(mockCreateClient).toHaveBeenCalledWith(
        expect.objectContaining({
          auth: 'ops-token-xyz',
        }),
      )
    })
  })

  // ---- acquireClient error paths ----

  describe('acquireClient error handling', () => {
    it('should throw BackendLockedError when SDK raises DesktopSessionExpiredError', async () => {
      mockCreateClient.mockRejectedValue(new MockDesktopSessionExpiredError('session expired'))

      const backend = makeSessionBackend()

      await expect(backend.list()).rejects.toBeInstanceOf(BackendLockedError)
    })

    it('should set interactive=true on BackendLockedError from session expiry', async () => {
      mockCreateClient.mockRejectedValue(new MockDesktopSessionExpiredError('session expired'))

      const backend = makeSessionBackend()

      await expect(backend.list()).rejects.toMatchObject({ interactive: true })
    })

    it('should throw AuthorizationDeniedError for generic createClient failures', async () => {
      mockCreateClient.mockRejectedValue(new Error('wrong account name'))

      const backend = makeSessionBackend()

      await expect(backend.list()).rejects.toBeInstanceOf(AuthorizationDeniedError)
    })

    it('should include the original error message in AuthorizationDeniedError', async () => {
      mockCreateClient.mockRejectedValue(new Error('wrong account name'))

      const backend = makeSessionBackend()

      await expect(backend.list()).rejects.toThrow('wrong account name')
    })

    it('should retry acquireClient on next call after a failure', async () => {
      mockCreateClient
        .mockRejectedValueOnce(new Error('transient'))
        .mockResolvedValueOnce(mockClient)

      const backend = makeSessionBackend()

      await expect(backend.list()).rejects.toBeInstanceOf(AuthorizationDeniedError)
      // Second call should retry and succeed
      const result = await backend.list()
      expect(result).toEqual([])
      expect(mockCreateClient).toHaveBeenCalledTimes(2)
    })
  })

  // ---- store ----

  describe('store', () => {
    it('should create a new item when the secret does not exist', async () => {
      const backend = makeSessionBackend()
      mockList.mockResolvedValue([]) // no existing items

      await backend.store('new-secret', 'secret-value')

      expect(mockCreate).toHaveBeenCalledWith(
        expect.objectContaining({
          vaultId: VAULT_ID,
          title: 'new-secret',
          tags: ['vaultkeeper'],
        }),
      )
      expect(mockPut).not.toHaveBeenCalled()
    })

    it('should update an existing item via put when secret already exists', async () => {
      const backend = makeSessionBackend()
      mockList.mockResolvedValue([makeOverview('item-1', 'my-secret')])
      mockGet.mockResolvedValue(makeItem('item-1', 'my-secret', 'old-value'))

      await backend.store('my-secret', 'new-value')

      expect(mockCreate).not.toHaveBeenCalled()
      expect(mockPut).toHaveBeenCalledTimes(1)
      const putArg: unknown = mockPut.mock.calls[0]?.[0]
      expect(putArg).toMatchObject({ id: 'item-1' })
      // Verify the password field was updated — check fields independently to avoid nested matchers
      const putFields: unknown = putArg !== null && typeof putArg === 'object' && 'fields' in putArg ? putArg.fields : undefined
      expect(putFields).toEqual(
        expect.arrayContaining([expect.objectContaining({ title: 'password', value: 'new-value' })]),
      )
    })

    it('should scope operations to the configured vaultId', async () => {
      const backend = new OnePasswordBackend({
        vault: 'specific-vault-id',
        account: 'acct',
      })
      mockList.mockResolvedValue([])
      await backend.store('key', 'val')

      expect(mockCreate).toHaveBeenCalledWith(
        expect.objectContaining({ vaultId: 'specific-vault-id' }),
      )
    })

    it('should create item with Concealed field type for the password', async () => {
      const backend = makeSessionBackend()
      mockList.mockResolvedValue([])

      await backend.store('my-secret', 'supersecret')

      expect(mockCreate).toHaveBeenCalledTimes(1)
      const createArg: unknown = mockCreate.mock.calls[0]?.[0]
      expect(createArg).toMatchObject({
        fields: [{ title: 'password', fieldType: 'Concealed', value: 'supersecret' }],
      })
    })
  })

  // ---- retrieve (session mode) ----

  describe('retrieve — session mode', () => {
    it('should return the secret value from the password field', async () => {
      const backend = makeSessionBackend()
      mockList.mockResolvedValue([makeOverview('item-1', 'my-secret')])
      mockGet.mockResolvedValue(makeItem('item-1', 'my-secret', 'hunter2'))

      const result = await backend.retrieve('my-secret')
      expect(result).toBe('hunter2')
    })

    it('should throw SecretNotFoundError when item is not in the vault', async () => {
      const backend = makeSessionBackend()
      mockList.mockResolvedValue([]) // empty vault

      await expect(backend.retrieve('missing-secret')).rejects.toBeInstanceOf(SecretNotFoundError)
    })

    it('should only find items tagged "vaultkeeper"', async () => {
      const backend = makeSessionBackend()
      // Item exists but without vaultkeeper tag — should not be found
      mockList.mockResolvedValue([makeOverview('item-1', 'my-secret', ['unrelated-tag'])])

      await expect(backend.retrieve('my-secret')).rejects.toBeInstanceOf(SecretNotFoundError)
    })

    it('should throw SecretNotFoundError when item exists but has no password field', async () => {
      const backend = makeSessionBackend()
      mockList.mockResolvedValue([makeOverview('item-1', 'my-secret')])
      mockGet.mockResolvedValue({
        ...makeItem('item-1', 'my-secret', ''),
        fields: [], // no fields at all
      })

      await expect(backend.retrieve('my-secret')).rejects.toBeInstanceOf(SecretNotFoundError)
    })
  })

  // ---- retrieve (per-access mode) ----

  describe('retrieve — per-access mode', () => {
    it('should spawn a child process and return its stdout value', async () => {
      const backend = makePerAccessBackend()
      const proc = makeWorkerProcess(JSON.stringify({ value: 'from-worker' }))
      mockSpawn.mockReturnValue(proc)

      const result = await backend.retrieve('my-secret')
      expect(result).toBe('from-worker')
      expect(mockSpawn).toHaveBeenCalledTimes(1)
    })

    it('should not use the session client for retrieve in per-access mode', async () => {
      const backend = makePerAccessBackend()
      const proc = makeWorkerProcess(JSON.stringify({ value: 'value' }))
      mockSpawn.mockReturnValue(proc)

      await backend.retrieve('my-secret')

      // createClient should not be called because per-access skips the session client for retrieve
      expect(mockCreateClient).not.toHaveBeenCalled()
    })

    it('should use session client for store in per-access mode', async () => {
      const backend = makePerAccessBackend()
      mockList.mockResolvedValue([])

      await backend.store('my-secret', 'val')

      expect(mockCreateClient).toHaveBeenCalledTimes(1)
      expect(mockSpawn).not.toHaveBeenCalled()
    })

    it('should use session client for delete in per-access mode', async () => {
      const backend = makePerAccessBackend()
      mockList.mockResolvedValue([makeOverview('item-1', 'my-secret')])

      await backend.delete('my-secret')

      expect(mockCreateClient).toHaveBeenCalledTimes(1)
      expect(mockSpawn).not.toHaveBeenCalled()
    })

    it('should use session client for exists in per-access mode', async () => {
      const backend = makePerAccessBackend()
      mockList.mockResolvedValue([makeOverview('item-1', 'my-secret')])

      await backend.exists('my-secret')

      expect(mockCreateClient).toHaveBeenCalledTimes(1)
      expect(mockSpawn).not.toHaveBeenCalled()
    })

    it('should use session client for list in per-access mode', async () => {
      const backend = makePerAccessBackend()
      mockList.mockResolvedValue([])

      await backend.list()

      expect(mockCreateClient).toHaveBeenCalledTimes(1)
      expect(mockSpawn).not.toHaveBeenCalled()
    })

    it('should throw SecretNotFoundError when worker returns NOT_FOUND code', async () => {
      const backend = makePerAccessBackend()
      const proc = makeWorkerProcess(JSON.stringify({ error: 'not found', code: 'NOT_FOUND' }))
      mockSpawn.mockReturnValue(proc)

      await expect(backend.retrieve('missing')).rejects.toBeInstanceOf(SecretNotFoundError)
    })

    it('should throw AuthorizationDeniedError when worker returns AUTH_DENIED code', async () => {
      const backend = makePerAccessBackend()
      const proc = makeWorkerProcess(JSON.stringify({ error: 'denied', code: 'AUTH_DENIED' }))
      mockSpawn.mockReturnValue(proc)

      await expect(backend.retrieve('my-secret')).rejects.toBeInstanceOf(AuthorizationDeniedError)
    })

    it('should throw BackendLockedError when worker returns LOCKED code', async () => {
      const backend = makePerAccessBackend()
      const proc = makeWorkerProcess(JSON.stringify({ error: 'locked', code: 'LOCKED' }))
      mockSpawn.mockReturnValue(proc)

      await expect(backend.retrieve('my-secret')).rejects.toBeInstanceOf(BackendLockedError)
    })

    it('should throw SecretNotFoundError for unknown worker error code (default case)', async () => {
      const backend = makePerAccessBackend()
      const proc = makeWorkerProcess(JSON.stringify({ error: 'something weird', code: 'INTERNAL' }))
      mockSpawn.mockReturnValue(proc)

      await expect(backend.retrieve('my-secret')).rejects.toBeInstanceOf(SecretNotFoundError)
    })

    it('should throw PluginNotFoundError when spawn itself errors', async () => {
      const backend = makePerAccessBackend()
      const proc = makeWorkerErrorProcess(new Error('spawn ENOENT'))
      mockSpawn.mockReturnValue(proc)

      await expect(backend.retrieve('my-secret')).rejects.toBeInstanceOf(PluginNotFoundError)
    })

    it('should throw SecretNotFoundError when worker returns unparseable output', async () => {
      const backend = makePerAccessBackend()
      const proc = makeWorkerProcess('not-valid-json{{')
      mockSpawn.mockReturnValue(proc)

      await expect(backend.retrieve('my-secret')).rejects.toBeInstanceOf(SecretNotFoundError)
    })

    it('should throw SecretNotFoundError when worker returns valid JSON with unexpected shape', async () => {
      const backend = makePerAccessBackend()
      const proc = makeWorkerProcess(JSON.stringify({ unexpected: true }))
      mockSpawn.mockReturnValue(proc)

      await expect(backend.retrieve('my-secret')).rejects.toBeInstanceOf(SecretNotFoundError)
    })
  })

  // ---- delete ----

  describe('delete', () => {
    it('should delete the item by vault and item id', async () => {
      const backend = makeSessionBackend()
      mockList.mockResolvedValue([makeOverview('item-1', 'my-secret')])

      await backend.delete('my-secret')

      expect(mockDelete).toHaveBeenCalledWith(VAULT_ID, 'item-1')
    })

    it('should throw SecretNotFoundError when item does not exist', async () => {
      const backend = makeSessionBackend()
      mockList.mockResolvedValue([])

      await expect(backend.delete('missing')).rejects.toBeInstanceOf(SecretNotFoundError)
    })
  })

  // ---- exists ----

  describe('exists', () => {
    it('should return true when a tagged item with that title exists', async () => {
      const backend = makeSessionBackend()
      mockList.mockResolvedValue([makeOverview('item-1', 'my-secret')])

      const result = await backend.exists('my-secret')
      expect(result).toBe(true)
    })

    it('should return false when no matching item exists', async () => {
      const backend = makeSessionBackend()
      mockList.mockResolvedValue([])

      const result = await backend.exists('missing')
      expect(result).toBe(false)
    })

    it('should return false when item exists but lacks vaultkeeper tag', async () => {
      const backend = makeSessionBackend()
      mockList.mockResolvedValue([makeOverview('item-1', 'my-secret', ['other-tag'])])

      const result = await backend.exists('my-secret')
      expect(result).toBe(false)
    })

    it('should propagate PluginNotFoundError from acquireClient', async () => {
      // When SDK isn't available, exists should throw, not silently return false
      mockCreateClient.mockRejectedValue(new MockDesktopSessionExpiredError('expired'))

      const backend = makeSessionBackend()

      await expect(backend.exists('my-secret')).rejects.toBeInstanceOf(BackendLockedError)
    })
  })

  // ---- list ----

  describe('list', () => {
    it('should return titles of all vaultkeeper-tagged items', async () => {
      const backend = makeSessionBackend()
      mockList.mockResolvedValue([
        makeOverview('item-1', 'secret-a'),
        makeOverview('item-2', 'secret-b'),
      ])

      const result = await backend.list()
      expect(result).toEqual(['secret-a', 'secret-b'])
    })

    it('should exclude items without the vaultkeeper tag', async () => {
      const backend = makeSessionBackend()
      mockList.mockResolvedValue([
        makeOverview('item-1', 'managed', ['vaultkeeper']),
        makeOverview('item-2', 'unmanaged', ['unrelated']),
      ])

      const result = await backend.list()
      expect(result).toEqual(['managed'])
    })

    it('should return empty array when vault has no items', async () => {
      const backend = makeSessionBackend()
      mockList.mockResolvedValue([])

      const result = await backend.list()
      expect(result).toEqual([])
    })

    it('should propagate errors from acquireClient', async () => {
      mockCreateClient.mockRejectedValue(new Error('network error'))

      const backend = makeSessionBackend()

      await expect(backend.list()).rejects.toBeInstanceOf(AuthorizationDeniedError)
    })
  })

  // ---- createClient timeout ----

  describe('session timeout', () => {
    it(
      'should throw BackendLockedError when createClient hangs beyond the session timeout',
      async () => {
        // createClient never resolves — simulates the known beta SDK hang
        mockCreateClient.mockReturnValue(new Promise<never>(() => { /* intentionally pending */ }))

        // Use a very short timeout (10ms) so the test runs in real time without fake timers
        const backend = new OnePasswordBackend({
          vault: VAULT_ID,
          account: ACCOUNT_NAME,
          sessionTimeoutMs: 10,
        })

        await expect(backend.store('any-key', 'any-val')).rejects.toBeInstanceOf(BackendLockedError)
      },
      // Give this test 2s to avoid the global 5s default being a problem
      2000,
    )
  })

  // ---- vault scoping ----

  describe('vault scoping', () => {
    it('should pass the configured vault ID to items.list', async () => {
      const backend = new OnePasswordBackend({ vault: 'target-vault', account: 'acct' })
      mockList.mockResolvedValue([])

      await backend.list()

      expect(mockList).toHaveBeenCalledWith('target-vault')
    })

    it('should pass the configured vault ID to items.delete', async () => {
      const backend = new OnePasswordBackend({ vault: 'target-vault', account: 'acct' })
      mockList.mockResolvedValue([makeOverview('item-1', 'my-secret')])

      await backend.delete('my-secret')

      expect(mockDelete).toHaveBeenCalledWith('target-vault', 'item-1')
    })
  })
})
