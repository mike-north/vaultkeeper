import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'

const configDir = '/tmp/vaultkeeper-test-config-dir'

// vi.hoisted ensures the mock factory can reference mockInit before imports are resolved.
const mockInit = vi.hoisted(() => vi.fn())
const mockDeleteFn = vi.hoisted(() => vi.fn().mockResolvedValue(undefined))
const mockGetTypes = vi.hoisted(() => vi.fn().mockReturnValue(['file']))
const mockCreate = vi.hoisted(() => vi.fn())

vi.mock('vaultkeeper', () => ({
  VaultKeeper: {
    init: mockInit,
  },
  BackendRegistry: {
    getTypes: mockGetTypes,
    create: mockCreate,
  },
}))

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

  describe('when delete succeeds', () => {
    it('should return 0', async () => {
      mockInit.mockResolvedValue({ delete: mockDeleteFn })
      const { deleteCommand } = await import('../../../src/commands/delete.js')
      const code = await deleteCommand(['--name', 'my-secret'], configDir)
      expect(code).toBe(0)
    })

    it('should write success message to stdout', async () => {
      mockInit.mockResolvedValue({ delete: mockDeleteFn })
      const { deleteCommand } = await import('../../../src/commands/delete.js')
      await deleteCommand(['--name', 'my-secret'], configDir)
      expect(stdoutOutput).toContain('deleted')
    })
  })

  describe('--skip-doctor flag', () => {
    it('should pass skipDoctor: false to VaultKeeper.init by default', async () => {
      mockInit.mockResolvedValue({ delete: mockDeleteFn })
      const { deleteCommand } = await import('../../../src/commands/delete.js')
      await deleteCommand(['--name', 'my-secret'], configDir)
      expect(mockInit).toHaveBeenCalledWith({ configDir, skipDoctor: false })
    })

    it('should pass skipDoctor: true to VaultKeeper.init when --skip-doctor is set', async () => {
      mockInit.mockResolvedValue({ delete: mockDeleteFn })
      const { deleteCommand } = await import('../../../src/commands/delete.js')
      await deleteCommand(['--name', 'my-secret', '--skip-doctor'], configDir)
      expect(mockInit).toHaveBeenCalledWith({ configDir, skipDoctor: true })
    })

    it('should pass skipDoctor: true when VAULTKEEPER_SKIP_DOCTOR=1 env var is set', async () => {
      process.env.VAULTKEEPER_SKIP_DOCTOR = '1'
      mockInit.mockResolvedValue({ delete: mockDeleteFn })
      const { deleteCommand } = await import('../../../src/commands/delete.js')
      await deleteCommand(['--name', 'my-secret'], configDir)
      expect(mockInit).toHaveBeenCalledWith({ configDir, skipDoctor: true })
    })

    it('should not skip doctor when VAULTKEEPER_SKIP_DOCTOR=0', async () => {
      process.env.VAULTKEEPER_SKIP_DOCTOR = '0'
      mockInit.mockResolvedValue({ delete: mockDeleteFn })
      const { deleteCommand } = await import('../../../src/commands/delete.js')
      await deleteCommand(['--name', 'my-secret'], configDir)
      expect(mockInit).toHaveBeenCalledWith({ configDir, skipDoctor: false })
    })

    it('should not skip doctor when VAULTKEEPER_SKIP_DOCTOR=true (non-numeric)', async () => {
      process.env.VAULTKEEPER_SKIP_DOCTOR = 'true'
      mockInit.mockResolvedValue({ delete: mockDeleteFn })
      const { deleteCommand } = await import('../../../src/commands/delete.js')
      await deleteCommand(['--name', 'my-secret'], configDir)
      expect(mockInit).toHaveBeenCalledWith({ configDir, skipDoctor: false })
    })

    it('should not skip doctor when VAULTKEEPER_SKIP_DOCTOR is empty string', async () => {
      process.env.VAULTKEEPER_SKIP_DOCTOR = ''
      mockInit.mockResolvedValue({ delete: mockDeleteFn })
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
