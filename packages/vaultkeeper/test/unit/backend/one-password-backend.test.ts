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
  BackendLockedError,
  BackendUnavailableError,
  AuthorizationDeniedError,
  PluginNotFoundError,
  ConfigValidationError,
  PresenceDeclinedError,
  PresenceTimeoutError,
} from '../../../src/errors.js'
import { PRESENCE_WRITE_TIMEOUT_MS } from '../../../src/backend/one-password-constants.js'

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
  stderr: {
    on: (event: string, cb: (chunk: Buffer) => void) => void
  }
  on: (event: string, cb: (...args: unknown[]) => void) => void
  /** Only present on write-path mocks; retrieve never writes to stdin. */
  stdin?: {
    write: (chunk: string, encoding?: string) => void
    end: () => void
  }
}

interface WorkerProcessOptions {
  stdout?: string
  stderr?: string
  exitCode?: number | null
}

/**
 * Set up a mock child process whose stdout/stderr emit `data` and then fires `close`.
 */
function makeWorkerProcess(stdoutDataOrOptions: string | WorkerProcessOptions): MockChildProcess {
  const opts: WorkerProcessOptions =
    typeof stdoutDataOrOptions === 'string' ? { stdout: stdoutDataOrOptions } : stdoutDataOrOptions
  const stdoutData = opts.stdout ?? ''
  const stderrData = opts.stderr ?? ''
  const exitCode = opts.exitCode ?? 0

  const stdoutListeners: ((chunk: Buffer) => void)[] = []
  const stderrListeners: ((chunk: Buffer) => void)[] = []
  const closeListeners: ((...args: unknown[]) => void)[] = []

  const stdout = {
    on: vi.fn((event: string, cb: (chunk: Buffer) => void) => {
      if (event === 'data') stdoutListeners.push(cb)
    }),
  }

  const stderr = {
    on: vi.fn((event: string, cb: (chunk: Buffer) => void) => {
      if (event === 'data') stderrListeners.push(cb)
    }),
  }

  const proc: MockChildProcess = {
    stdout,
    stderr,
    on: vi.fn((event: string, cb: (...args: unknown[]) => void) => {
      if (event === 'close') closeListeners.push(cb)
    }),
  }

  // Schedule emission after mock resolves
  setTimeout(() => {
    if (stdoutData !== '') {
      for (const listener of stdoutListeners) {
        listener(Buffer.from(stdoutData, 'utf8'))
      }
    }
    if (stderrData !== '') {
      for (const listener of stderrListeners) {
        listener(Buffer.from(stderrData, 'utf8'))
      }
    }
    for (const listener of closeListeners) {
      listener(exitCode)
    }
  }, 0)

  return proc
}

function makeWorkerErrorProcess(spawnErr: Error): MockChildProcess {
  const errorListeners: ((...args: unknown[]) => void)[] = []

  const stdout = { on: vi.fn() }
  const stderr = { on: vi.fn() }
  // Present so a write-path spawn error (store, which writes to stdin before
  // the 'error' event fires) doesn't throw on a missing `.stdin` — retrieve
  // and delete never touch it.
  const stdin = { on: vi.fn(), write: vi.fn(), end: vi.fn() }

  const proc: MockChildProcess = {
    stdout,
    stderr,
    stdin,
    on: vi.fn((event: string, cb: (...args: unknown[]) => void) => {
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

/** Records what a mock write-worker's stdin received, for argv-hygiene assertions. */
interface StdinRecorder {
  writes: string[]
  ended: boolean
}

interface MockWriteChildProcess extends MockChildProcess {
  stdin: {
    write: (chunk: string, encoding?: string) => void
    end: () => void
  }
}

/**
 * Set up a mock child process for the `store`/`delete` write path — same
 * stdout/stderr/close wiring as {@link makeWorkerProcess}, plus a `stdin` that
 * records what was written so tests can assert the secret value travelled via
 * stdin, never argv.
 */
function makeWorkerWriteProcess(
  stdoutDataOrOptions: string | WorkerProcessOptions,
  stdinRecorder?: StdinRecorder,
): MockWriteChildProcess {
  const opts: WorkerProcessOptions =
    typeof stdoutDataOrOptions === 'string' ? { stdout: stdoutDataOrOptions } : stdoutDataOrOptions
  const stdoutData = opts.stdout ?? ''
  const stderrData = opts.stderr ?? ''
  const exitCode = opts.exitCode ?? 0

  const stdoutListeners: ((chunk: Buffer) => void)[] = []
  const stderrListeners: ((chunk: Buffer) => void)[] = []
  const closeListeners: ((...args: unknown[]) => void)[] = []

  const stdout = {
    on: vi.fn((event: string, cb: (chunk: Buffer) => void) => {
      if (event === 'data') stdoutListeners.push(cb)
    }),
  }
  const stderr = {
    on: vi.fn((event: string, cb: (chunk: Buffer) => void) => {
      if (event === 'data') stderrListeners.push(cb)
    }),
  }
  const stdin = {
    on: vi.fn(),
    write: vi.fn((chunk: string) => {
      stdinRecorder?.writes.push(chunk)
    }),
    end: vi.fn(() => {
      if (stdinRecorder !== undefined) {
        stdinRecorder.ended = true
      }
    }),
  }

  const proc: MockWriteChildProcess = {
    stdout,
    stderr,
    stdin,
    on: vi.fn((event: string, cb: (...args: unknown[]) => void) => {
      if (event === 'close') closeListeners.push(cb)
    }),
  }

  setTimeout(() => {
    if (stdoutData !== '') {
      for (const listener of stdoutListeners) {
        listener(Buffer.from(stdoutData, 'utf8'))
      }
    }
    if (stderrData !== '') {
      for (const listener of stderrListeners) {
        listener(Buffer.from(stderrData, 'utf8'))
      }
    }
    for (const listener of closeListeners) {
      listener(exitCode)
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

    // Regression: issue #127 — this previously threw a plain `Error`,
    // breaking instanceof-based handling. It must now throw a typed
    // ConfigValidationError naming the offending options field.
    it('should throw a typed ConfigValidationError when per-access mode is combined with serviceAccountToken', () => {
      try {
        new OnePasswordBackend({
          vault: VAULT_ID,
          serviceAccountToken: 'token',
          accessMode: 'per-access',
        })
        expect.unreachable('constructor should have thrown')
      } catch (err) {
        if (!(err instanceof ConfigValidationError)) {
          throw err
        }
        expect(err.field).toBe('options.accessMode')
      }
    })

    it('should throw when both account and serviceAccountToken are provided', () => {
      expect(
        () =>
          new OnePasswordBackend({
            vault: VAULT_ID,
            account: 'my-account',
            serviceAccountToken: 'token',
          }),
      ).toThrow('account and serviceAccountToken are mutually exclusive')
    })

    // Regression: issue #127 — this previously threw a plain `Error`,
    // breaking instanceof-based handling. It must now throw a typed
    // ConfigValidationError naming the offending options field.
    it('should throw a typed ConfigValidationError when both account and serviceAccountToken are provided', () => {
      try {
        new OnePasswordBackend({
          vault: VAULT_ID,
          account: 'my-account',
          serviceAccountToken: 'token',
        })
        expect.unreachable('constructor should have thrown')
      } catch (err) {
        if (!(err instanceof ConfigValidationError)) {
          throw err
        }
        expect(err.field).toBe('options.serviceAccountToken')
      }
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
      const putFields: unknown =
        putArg !== null && typeof putArg === 'object' && 'fields' in putArg
          ? putArg.fields
          : undefined
      expect(putFields).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ title: 'password', value: 'new-value' }),
        ]),
      )
    })

    it('should append a password field when updating an item that is missing one', async () => {
      const backend = makeSessionBackend()
      const itemWithoutPassword = {
        id: 'item-1',
        title: 'my-secret',
        tags: ['vaultkeeper'],
        fields: [{ id: 'notes', title: 'notes', fieldType: 'Text', value: 'some note' }],
        vaultId: VAULT_ID,
        category: 'Password',
        version: 1,
      }
      mockList.mockResolvedValue([makeOverview('item-1', 'my-secret')])
      mockGet.mockResolvedValue(itemWithoutPassword)

      await backend.store('my-secret', 'new-value')

      expect(mockPut).toHaveBeenCalledTimes(1)
      const putArg: unknown = mockPut.mock.calls[0]?.[0]
      const putFields: unknown =
        putArg !== null && typeof putArg === 'object' && 'fields' in putArg
          ? putArg.fields
          : undefined
      expect(putFields).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            title: 'password',
            value: 'new-value',
            fieldType: 'Concealed',
          }),
        ]),
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
      // An unrecognized code (not one of the explicitly handled ones) falls
      // through to the default branch.
      const proc = makeWorkerProcess(
        JSON.stringify({ error: 'something weird', code: 'SOMETHING_UNKNOWN' }),
      )
      mockSpawn.mockReturnValue(proc)

      await expect(backend.retrieve('my-secret')).rejects.toBeInstanceOf(SecretNotFoundError)
    })

    // Regression: issue #127 — this previously rejected with a plain `Error`,
    // breaking instanceof-based handling. It must now reject with a typed
    // BackendUnavailableError.
    it('should throw a typed BackendUnavailableError with worker path when spawn itself errors', async () => {
      const backend = makePerAccessBackend()
      const proc = makeWorkerErrorProcess(new Error('spawn ENOENT'))
      mockSpawn.mockReturnValue(proc)

      try {
        await backend.retrieve('my-secret')
        expect.unreachable('retrieve should have rejected')
      } catch (err) {
        if (!(err instanceof BackendUnavailableError)) {
          throw err
        }
        expect(err.message).toContain('Failed to spawn 1Password per-access worker')
        expect(err.reason).toBe('worker-spawn-failed')
        expect(err.attempted).toEqual(['1password'])
      }
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

    it('should throw Error with stderr when worker crashes with no stdout', async () => {
      const backend = makePerAccessBackend()
      const proc = makeWorkerProcess({
        stdout: '',
        stderr: 'Error: Cannot find module @1password/sdk',
        exitCode: 1,
      })
      mockSpawn.mockReturnValue(proc)

      await expect(backend.retrieve('my-secret')).rejects.toThrow(
        'Cannot find module @1password/sdk',
      )
    })

    it('should throw Error with exit code when worker crashes with no stdout or stderr', async () => {
      const backend = makePerAccessBackend()
      const proc = makeWorkerProcess({ stdout: '', stderr: '', exitCode: 137 })
      mockSpawn.mockReturnValue(proc)

      await expect(backend.retrieve('my-secret')).rejects.toThrow('exit code 137')
    })

    // Regression: issue #127 — a worker crash with no stdout previously
    // rejected with a plain `Error`, breaking instanceof-based handling. It
    // must now reject with a typed BackendUnavailableError.
    it('should throw a typed BackendUnavailableError when worker crashes with no stdout', async () => {
      const backend = makePerAccessBackend()
      const proc = makeWorkerProcess({ stdout: '', stderr: '', exitCode: 137 })
      mockSpawn.mockReturnValue(proc)

      try {
        await backend.retrieve('my-secret')
        expect.unreachable('retrieve should have rejected')
      } catch (err) {
        if (!(err instanceof BackendUnavailableError)) {
          throw err
        }
        expect(err.reason).toBe('worker-crashed')
        expect(err.attempted).toEqual(['1password'])
      }
    })

    // Regression for https://github.com/mike-north/vaultkeeper/issues/113: when
    // the optional @1password/sdk peer is absent, the per-access worker reports
    // a PLUGIN_NOT_FOUND code that the backend must surface as a typed
    // PluginNotFoundError naming the missing dependency — not a raw crash.
    it('should throw PluginNotFoundError when worker reports the SDK is missing', async () => {
      const backend = makePerAccessBackend()
      const proc = makeWorkerProcess(
        JSON.stringify({
          error: '1Password SDK (@1password/sdk) is not installed',
          code: 'PLUGIN_NOT_FOUND',
        }),
      )
      mockSpawn.mockReturnValue(proc)

      const error = await backend.retrieve('my-secret').catch((err: unknown) => err)
      expect(error).toBeInstanceOf(PluginNotFoundError)
      expect(error).toMatchObject({ plugin: '@1password/sdk' })
    })

    // Regression for https://github.com/mike-north/vaultkeeper/issues/113: a
    // present-but-broken SDK makes the worker report an INTERNAL failure with
    // the real load error. The backend must classify that as a backend problem
    // — NOT a missing plugin (reinstall hint) and NOT a missing secret — while
    // preserving the worker's real detail.
    it('should reject INTERNAL worker failures as a backend error preserving the detail', async () => {
      const backend = makePerAccessBackend()
      const proc = makeWorkerProcess(
        JSON.stringify({
          error: 'Failed to load 1Password SDK: Error: native binding failed',
          code: 'INTERNAL',
        }),
      )
      mockSpawn.mockReturnValue(proc)

      const error = await backend.retrieve('my-secret').catch((err: unknown) => err)
      expect(error).toBeInstanceOf(BackendUnavailableError)
      expect(error).not.toBeInstanceOf(PluginNotFoundError)
      expect(error).not.toBeInstanceOf(SecretNotFoundError)
      // The real load error text is preserved, not swapped for a "reinstall" hint.
      expect(error instanceof Error ? error.message : '').toContain('native binding failed')
    })
  })

  // ---- store (per-access mode) — issue #211 ----

  describe('store — per-access mode', () => {
    it('should spawn a worker forcing a fresh action instead of using the session client', async () => {
      const backend = makePerAccessBackend()
      const proc = makeWorkerWriteProcess(JSON.stringify({ ok: true }))
      mockSpawn.mockReturnValue(proc)

      await backend.store('my-secret', 'hunter2')

      expect(mockSpawn).toHaveBeenCalledTimes(1)
      expect(mockCreateClient).not.toHaveBeenCalled()
    })

    // Regression: issue #211 — before the write path existed, per-access store
    // silently routed through the cached session client, so a
    // --require-presence-per-use store never forced a fresh action. This pins
    // the fix: store must go through the worker in per-access mode.
    it('should force a fresh action for each store call (two stores spawn two workers)', async () => {
      const backend = makePerAccessBackend()
      mockSpawn
        .mockReturnValueOnce(makeWorkerWriteProcess(JSON.stringify({ ok: true })))
        .mockReturnValueOnce(makeWorkerWriteProcess(JSON.stringify({ ok: true })))

      await backend.store('a', '1')
      await backend.store('b', '2')

      expect(mockSpawn).toHaveBeenCalledTimes(2)
    })

    it('should deliver the secret value via stdin, never as a spawn argument (argv hygiene)', async () => {
      const backend = makePerAccessBackend()
      const stdinRecorder: StdinRecorder = { writes: [], ended: false }
      const proc = makeWorkerWriteProcess(JSON.stringify({ ok: true }), stdinRecorder)
      mockSpawn.mockReturnValue(proc)

      await backend.store('my-secret', 'super-secret-value')

      // The secret must never appear among the spawn arguments.
      const spawnArgs: unknown = mockSpawn.mock.calls[0]?.[1]
      expect(Array.isArray(spawnArgs)).toBe(true)
      if (Array.isArray(spawnArgs)) {
        for (const arg of spawnArgs) {
          expect(arg).not.toContain('super-secret-value')
        }
      }
      // It travelled over stdin instead, and stdin was closed.
      expect(stdinRecorder.writes.join('')).toBe('super-secret-value')
      expect(stdinRecorder.ended).toBe(true)
    })

    it('should pass the store op and secret id as spawn arguments', async () => {
      const backend = makePerAccessBackend()
      const proc = makeWorkerWriteProcess(JSON.stringify({ ok: true }))
      mockSpawn.mockReturnValue(proc)

      await backend.store('my-secret', 'v')

      const spawnArgs: unknown = mockSpawn.mock.calls[0]?.[1]
      expect(spawnArgs).toEqual(
        expect.arrayContaining([
          expect.stringContaining('one-password-worker'),
          'my-secret',
          'store',
        ]),
      )
    })

    it('should throw PresenceDeclinedError when the worker reports PRESENCE_DECLINED', async () => {
      const backend = makePerAccessBackend()
      const proc = makeWorkerWriteProcess(
        JSON.stringify({ error: 'presence action declined', code: 'PRESENCE_DECLINED' }),
      )
      mockSpawn.mockReturnValue(proc)

      await expect(backend.store('my-secret', 'v')).rejects.toBeInstanceOf(PresenceDeclinedError)
    })

    it('should throw PresenceTimeoutError with the configured timeout when the worker reports PRESENCE_TIMEOUT', async () => {
      const backend = makePerAccessBackend()
      const proc = makeWorkerWriteProcess(
        JSON.stringify({ error: 'no fresh action within window', code: 'PRESENCE_TIMEOUT' }),
      )
      mockSpawn.mockReturnValue(proc)

      const error = await backend.store('my-secret', 'v').catch((err: unknown) => err)
      expect(error).toBeInstanceOf(PresenceTimeoutError)
      if (error instanceof PresenceTimeoutError) {
        expect(error.timeoutMs).toBe(PRESENCE_WRITE_TIMEOUT_MS)
        expect(error.backendType).toBe('1password')
      }
      expect(error).not.toBeInstanceOf(PresenceDeclinedError)
    })

    it('should throw BackendLockedError when the worker reports LOCKED', async () => {
      const backend = makePerAccessBackend()
      const proc = makeWorkerWriteProcess(JSON.stringify({ error: 'locked', code: 'LOCKED' }))
      mockSpawn.mockReturnValue(proc)

      await expect(backend.store('my-secret', 'v')).rejects.toBeInstanceOf(BackendLockedError)
    })

    it('should throw PluginNotFoundError when the worker reports PLUGIN_NOT_FOUND', async () => {
      const backend = makePerAccessBackend()
      const proc = makeWorkerWriteProcess(
        JSON.stringify({ error: 'SDK not installed', code: 'PLUGIN_NOT_FOUND' }),
      )
      mockSpawn.mockReturnValue(proc)

      await expect(backend.store('my-secret', 'v')).rejects.toBeInstanceOf(PluginNotFoundError)
    })

    it('should throw a typed BackendUnavailableError when the worker reports INTERNAL', async () => {
      const backend = makePerAccessBackend()
      const proc = makeWorkerWriteProcess(
        JSON.stringify({ error: 'unexpected failure', code: 'INTERNAL' }),
      )
      mockSpawn.mockReturnValue(proc)

      const error = await backend.store('my-secret', 'v').catch((err: unknown) => err)
      expect(error).toBeInstanceOf(BackendUnavailableError)
      expect(error instanceof Error ? error.message : '').toContain('unexpected failure')
    })

    it('should throw a typed BackendUnavailableError when worker output is unparseable', async () => {
      const backend = makePerAccessBackend()
      const proc = makeWorkerWriteProcess('not-valid-json{{')
      mockSpawn.mockReturnValue(proc)

      await expect(backend.store('my-secret', 'v')).rejects.toBeInstanceOf(BackendUnavailableError)
    })

    // Regression for the PR #222 review thread (comment 3592005272): a
    // malformed worker response carrying BOTH `ok: false` and an error/code
    // pair passes the response-shape guard via its failure branch. The
    // success narrowing must check ok's VALUE, not mere key presence — this
    // response is a failed write and must never be classified as success.
    it('treats an { ok: false, error, code } worker response as a failure, never success', async () => {
      const backend = makePerAccessBackend()
      const proc = makeWorkerWriteProcess(
        JSON.stringify({ ok: false, error: 'write exploded', code: 'INTERNAL' }),
      )
      mockSpawn.mockReturnValue(proc)

      await expect(backend.store('my-secret', 'v')).rejects.toBeInstanceOf(BackendUnavailableError)
    })

    it('should throw a typed BackendUnavailableError when the worker crashes with no stdout', async () => {
      const backend = makePerAccessBackend()
      const proc = makeWorkerWriteProcess({ stdout: '', stderr: '', exitCode: 137 })
      mockSpawn.mockReturnValue(proc)

      const error = await backend.store('my-secret', 'v').catch((err: unknown) => err)
      expect(error).toBeInstanceOf(BackendUnavailableError)
      if (error instanceof BackendUnavailableError) {
        expect(error.reason).toBe('worker-crashed')
      }
    })

    it('should throw a typed BackendUnavailableError when spawn itself errors', async () => {
      const backend = makePerAccessBackend()
      const proc = makeWorkerErrorProcess(new Error('spawn ENOENT'))
      mockSpawn.mockReturnValue(proc)

      const error = await backend.store('my-secret', 'v').catch((err: unknown) => err)
      expect(error).toBeInstanceOf(BackendUnavailableError)
      if (error instanceof BackendUnavailableError) {
        expect(error.reason).toBe('worker-spawn-failed')
      }
    })
  })

  // ---- delete (per-access mode) — issue #211 ----

  describe('delete — per-access mode', () => {
    it('should spawn a worker forcing a fresh action instead of using the session client', async () => {
      const backend = makePerAccessBackend()
      const proc = makeWorkerWriteProcess(JSON.stringify({ ok: true }))
      mockSpawn.mockReturnValue(proc)

      await backend.delete('my-secret')

      expect(mockSpawn).toHaveBeenCalledTimes(1)
      expect(mockCreateClient).not.toHaveBeenCalled()
    })

    it('should not write anything to stdin (no secret value to send)', async () => {
      const stdinRecorder: StdinRecorder = { writes: [], ended: false }
      const backend = makePerAccessBackend()
      const proc = makeWorkerWriteProcess(JSON.stringify({ ok: true }), stdinRecorder)
      mockSpawn.mockReturnValue(proc)

      await backend.delete('my-secret')

      expect(stdinRecorder.writes).toEqual([])
    })

    it('should throw SecretNotFoundError when the worker reports NOT_FOUND', async () => {
      const backend = makePerAccessBackend()
      const proc = makeWorkerWriteProcess(JSON.stringify({ error: 'not found', code: 'NOT_FOUND' }))
      mockSpawn.mockReturnValue(proc)

      await expect(backend.delete('missing')).rejects.toBeInstanceOf(SecretNotFoundError)
    })

    it('should throw PresenceDeclinedError when the worker reports PRESENCE_DECLINED', async () => {
      const backend = makePerAccessBackend()
      const proc = makeWorkerWriteProcess(
        JSON.stringify({ error: 'presence action declined', code: 'PRESENCE_DECLINED' }),
      )
      mockSpawn.mockReturnValue(proc)

      await expect(backend.delete('my-secret')).rejects.toBeInstanceOf(PresenceDeclinedError)
    })

    it('should throw PresenceTimeoutError when the worker reports PRESENCE_TIMEOUT', async () => {
      const backend = makePerAccessBackend()
      const proc = makeWorkerWriteProcess(
        JSON.stringify({ error: 'no fresh action within window', code: 'PRESENCE_TIMEOUT' }),
      )
      mockSpawn.mockReturnValue(proc)

      await expect(backend.delete('my-secret')).rejects.toBeInstanceOf(PresenceTimeoutError)
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
    // 2s test timeout keeps this well under the global 5s default while leaving
    // ample room over the backend's 10ms sessionTimeoutMs.
    it('should throw BackendLockedError when createClient hangs beyond the session timeout', async () => {
      // createClient never resolves — simulates the known beta SDK hang
      mockCreateClient.mockReturnValue(
        new Promise<never>(() => {
          /* intentionally pending */
        }),
      )

      // Use a very short timeout (10ms) so the test runs in real time without fake timers
      const backend = new OnePasswordBackend({
        vault: VAULT_ID,
        account: ACCOUNT_NAME,
        sessionTimeoutMs: 10,
      })

      await expect(backend.store('any-key', 'any-val')).rejects.toBeInstanceOf(BackendLockedError)
    }, 2000)
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
