import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'

const configDir = '/tmp/vaultkeeper-test-config-dir'

// vi.hoisted ensures the mock factory can reference mockInit before imports are resolved.
const mockInit = vi.hoisted(() => vi.fn())
const mockDeleteFn = vi.hoisted(() => vi.fn().mockResolvedValue(undefined))
const mockGetTypes = vi.hoisted(() => vi.fn().mockReturnValue(['file']))
const mockCreate = vi.hoisted(() => vi.fn())

// Partial mock: keep real exports (e.g. ConfigParseError/ConfigValidationError,
// needed by formatError's instanceof checks — issue #114) alongside the
// mocked entry points this suite controls.
vi.mock('vaultkeeper', async (importOriginal) => {
  const actual = await importOriginal<typeof import('vaultkeeper')>()
  return {
    ...actual,
    VaultKeeper: {
      init: mockInit,
    },
    BackendRegistry: {
      getTypes: mockGetTypes,
      create: mockCreate,
    },
    defaultBackendType: vi.fn().mockReturnValue('file'),
  }
})

describe('deleteCommand', () => {
  let stderrOutput: string
  let stdoutOutput: string

  beforeEach(() => {
    stderrOutput = ''
    stdoutOutput = ''
    vi.spyOn(process.stderr, 'write').mockImplementation((chunk) => {
      stderrOutput += String(chunk)
      return true
    })
    vi.spyOn(process.stdout, 'write').mockImplementation((chunk) => {
      stdoutOutput += String(chunk)
      return true
    })
    mockGetTypes.mockReturnValue(['file'])
    mockDeleteFn.mockResolvedValue(undefined)
    mockCreate.mockReturnValue({ delete: mockDeleteFn })
  })

  afterEach(() => {
    vi.restoreAllMocks()
    vi.clearAllMocks()
    delete process.env.VAULTKEEPER_SKIP_DOCTOR
  })

  describe('--name flag validation', () => {
    it('should return 2 when --name is missing', async () => {
      const { deleteCommand } = await import('../../../src/commands/delete.js')
      const code = await deleteCommand([], configDir)
      expect(code).toBe(2)
    })

    it('should write error to stderr when --name is missing', async () => {
      const { deleteCommand } = await import('../../../src/commands/delete.js')
      await deleteCommand([], configDir)
      expect(stderrOutput).toContain('--name is required')
    })

    it('should include usage hint when --name is missing', async () => {
      const { deleteCommand } = await import('../../../src/commands/delete.js')
      await deleteCommand([], configDir)
      expect(stderrOutput).toContain('Usage:')
    })
  })

  describe('when VaultKeeper.init() throws', () => {
    it('should return 1', async () => {
      mockInit.mockRejectedValue(new Error('backend unavailable'))
      const { deleteCommand } = await import('../../../src/commands/delete.js')
      const code = await deleteCommand(['--name', 'my-secret'], configDir)
      expect(code).toBe(1)
    })

    it('should write formatted error to stderr', async () => {
      mockInit.mockRejectedValue(new Error('backend unavailable'))
      const { deleteCommand } = await import('../../../src/commands/delete.js')
      await deleteCommand(['--name', 'my-secret'], configDir)
      expect(stderrOutput).toContain('backend unavailable')
    })
  })

  // deleteCommand pre-checks existence via vault.secretExists() before calling
  // vault.delete() (issue #118), so the mocked vault must implement both.
  function existingSecretVault(): {
    delete: typeof mockDeleteFn
    secretExists: ReturnType<typeof vi.fn>
    activeBackendType: string
  } {
    return {
      delete: mockDeleteFn,
      secretExists: vi.fn().mockResolvedValue(true),
      activeBackendType: 'file',
    }
  }

  describe('when delete succeeds', () => {
    it('should return 0', async () => {
      mockInit.mockResolvedValue(existingSecretVault())
      const { deleteCommand } = await import('../../../src/commands/delete.js')
      const code = await deleteCommand(['--name', 'my-secret'], configDir)
      expect(code).toBe(0)
    })

    it('should write success message to stdout', async () => {
      mockInit.mockResolvedValue(existingSecretVault())
      const { deleteCommand } = await import('../../../src/commands/delete.js')
      await deleteCommand(['--name', 'my-secret'], configDir)
      expect(stdoutOutput).toContain('deleted')
    })
  })

  // Regression: issue #118 — delete previously relied on the file backend's
  // own SecretNotFoundError ("Secret not found in file store: x"), worded
  // differently from exec's ("Secret "x" not found in file backend") and with
  // no recovery hint. delete now pre-checks existence and reports the same
  // wording + hint exec.ts does.
  describe('when the secret does not exist (issue #118)', () => {
    it('should return 1 and report a consistent SecretNotFoundError with a recovery hint', async () => {
      mockInit.mockResolvedValue({
        delete: mockDeleteFn,
        secretExists: vi.fn().mockResolvedValue(false),
        activeBackendType: 'file',
      })
      const { deleteCommand } = await import('../../../src/commands/delete.js')
      const code = await deleteCommand(['--name', 'missing-secret'], configDir)
      expect(code).toBe(1)
      expect(stderrOutput).toContain('SecretNotFoundError')
      expect(stderrOutput).toContain('Secret "missing-secret" not found in the "file" backend')
      expect(stderrOutput).toContain('Run `vaultkeeper store --name missing-secret` to create it')
      expect(mockDeleteFn).not.toHaveBeenCalled()
    })
  })

  describe('--skip-doctor flag', () => {
    it('should pass skipDoctor: false to VaultKeeper.init by default', async () => {
      mockInit.mockResolvedValue(existingSecretVault())
      const { deleteCommand } = await import('../../../src/commands/delete.js')
      await deleteCommand(['--name', 'my-secret'], configDir)
      expect(mockInit).toHaveBeenCalledWith({ configDir, skipDoctor: false })
    })

    it('should pass skipDoctor: true to VaultKeeper.init when --skip-doctor is set', async () => {
      mockInit.mockResolvedValue(existingSecretVault())
      const { deleteCommand } = await import('../../../src/commands/delete.js')
      await deleteCommand(['--name', 'my-secret', '--skip-doctor'], configDir)
      expect(mockInit).toHaveBeenCalledWith({ configDir, skipDoctor: true })
    })

    it('should pass skipDoctor: true when VAULTKEEPER_SKIP_DOCTOR=1 env var is set', async () => {
      process.env.VAULTKEEPER_SKIP_DOCTOR = '1'
      mockInit.mockResolvedValue(existingSecretVault())
      const { deleteCommand } = await import('../../../src/commands/delete.js')
      await deleteCommand(['--name', 'my-secret'], configDir)
      expect(mockInit).toHaveBeenCalledWith({ configDir, skipDoctor: true })
    })

    it('should not skip doctor when VAULTKEEPER_SKIP_DOCTOR=0', async () => {
      process.env.VAULTKEEPER_SKIP_DOCTOR = '0'
      mockInit.mockResolvedValue(existingSecretVault())
      const { deleteCommand } = await import('../../../src/commands/delete.js')
      await deleteCommand(['--name', 'my-secret'], configDir)
      expect(mockInit).toHaveBeenCalledWith({ configDir, skipDoctor: false })
    })

    it('should not skip doctor when VAULTKEEPER_SKIP_DOCTOR=true (non-numeric)', async () => {
      process.env.VAULTKEEPER_SKIP_DOCTOR = 'true'
      mockInit.mockResolvedValue(existingSecretVault())
      const { deleteCommand } = await import('../../../src/commands/delete.js')
      await deleteCommand(['--name', 'my-secret'], configDir)
      expect(mockInit).toHaveBeenCalledWith({ configDir, skipDoctor: false })
    })

    it('should not skip doctor when VAULTKEEPER_SKIP_DOCTOR is empty string', async () => {
      process.env.VAULTKEEPER_SKIP_DOCTOR = ''
      mockInit.mockResolvedValue(existingSecretVault())
      const { deleteCommand } = await import('../../../src/commands/delete.js')
      await deleteCommand(['--name', 'my-secret'], configDir)
      expect(mockInit).toHaveBeenCalledWith({ configDir, skipDoctor: false })
    })
  })

  describe('--help flag', () => {
    it('should include --skip-doctor in help output', async () => {
      const { deleteCommand } = await import('../../../src/commands/delete.js')
      await deleteCommand(['--help'], configDir)
      expect(stdoutOutput).toContain('--skip-doctor')
    })

    it('should include VAULTKEEPER_SKIP_DOCTOR env var in help output', async () => {
      const { deleteCommand } = await import('../../../src/commands/delete.js')
      await deleteCommand(['--help'], configDir)
      expect(stdoutOutput).toContain('VAULTKEEPER_SKIP_DOCTOR')
    })
  })
})
