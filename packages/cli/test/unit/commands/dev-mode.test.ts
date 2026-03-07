import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'

// vi.hoisted ensures the mock factory can reference mockInit before imports are resolved.
const mockInit = vi.hoisted(() => vi.fn())

vi.mock('vaultkeeper', () => ({
  VaultKeeper: {
    init: mockInit,
  },
}))

describe('devModeCommand', () => {
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
  })

  afterEach(() => {
    vi.restoreAllMocks()
    vi.clearAllMocks()
    delete process.env.VAULTKEEPER_SKIP_DOCTOR
  })

  describe('action validation', () => {
    it('should return 2 when no action is provided', async () => {
      const { devModeCommand } = await import('../../../src/commands/dev-mode.js')
      const code = await devModeCommand(['--script', '/path/to/script.sh'])
      expect(code).toBe(2)
    })

    it('should return 2 for invalid action', async () => {
      const { devModeCommand } = await import('../../../src/commands/dev-mode.js')
      const code = await devModeCommand(['invalid', '--script', '/path/to/script.sh'])
      expect(code).toBe(2)
    })

    it('should return 2 for action that is neither enable nor disable', async () => {
      const { devModeCommand } = await import('../../../src/commands/dev-mode.js')
      const code = await devModeCommand(['toggle', '--script', '/path/to/script.sh'])
      expect(code).toBe(2)
    })

    it('should write usage to stderr for invalid action', async () => {
      const { devModeCommand } = await import('../../../src/commands/dev-mode.js')
      await devModeCommand(['invalid', '--script', '/path/to/script.sh'])
      expect(stderrOutput).toContain('Usage: vaultkeeper dev-mode')
      expect(stderrOutput).toContain('<enable|disable>')
    })
  })

  describe('--script flag validation', () => {
    it('should return 2 when --script is missing with valid action', async () => {
      const { devModeCommand } = await import('../../../src/commands/dev-mode.js')
      const code = await devModeCommand(['enable'])
      expect(code).toBe(2)
    })

    it('should return 2 when --script is missing with disable action', async () => {
      const { devModeCommand } = await import('../../../src/commands/dev-mode.js')
      const code = await devModeCommand(['disable'])
      expect(code).toBe(2)
    })

    it('should write usage to stderr when --script is missing', async () => {
      const { devModeCommand } = await import('../../../src/commands/dev-mode.js')
      await devModeCommand(['enable'])
      expect(stderrOutput).toContain('--script')
    })
  })

  describe('when both action and --script are missing', () => {
    it('should return 2 with no args', async () => {
      const { devModeCommand } = await import('../../../src/commands/dev-mode.js')
      const code = await devModeCommand([])
      expect(code).toBe(2)
    })

    it('should write usage to stderr with no args', async () => {
      const { devModeCommand } = await import('../../../src/commands/dev-mode.js')
      await devModeCommand([])
      expect(stderrOutput).toContain('Usage:')
    })
  })

  describe('--skip-doctor flag', () => {
    it('should pass skipDoctor: false to VaultKeeper.init by default', async () => {
      const mockVault = { setDevelopmentMode: vi.fn().mockResolvedValue(undefined) }
      mockInit.mockResolvedValue(mockVault)
      const { devModeCommand } = await import('../../../src/commands/dev-mode.js')
      await devModeCommand(['enable', '--script', '/path/to/script.sh'])
      expect(mockInit).toHaveBeenCalledWith({ skipDoctor: false })
    })

    it('should pass skipDoctor: true to VaultKeeper.init when --skip-doctor is set', async () => {
      const mockVault = { setDevelopmentMode: vi.fn().mockResolvedValue(undefined) }
      mockInit.mockResolvedValue(mockVault)
      const { devModeCommand } = await import('../../../src/commands/dev-mode.js')
      await devModeCommand(['enable', '--script', '/path/to/script.sh', '--skip-doctor'])
      expect(mockInit).toHaveBeenCalledWith({ skipDoctor: true })
    })

    it('should pass skipDoctor: true when VAULTKEEPER_SKIP_DOCTOR=1 env var is set', async () => {
      process.env.VAULTKEEPER_SKIP_DOCTOR = '1'
      const mockVault = { setDevelopmentMode: vi.fn().mockResolvedValue(undefined) }
      mockInit.mockResolvedValue(mockVault)
      const { devModeCommand } = await import('../../../src/commands/dev-mode.js')
      await devModeCommand(['enable', '--script', '/path/to/script.sh'])
      expect(mockInit).toHaveBeenCalledWith({ skipDoctor: true })
    })

    it('should not skip doctor when VAULTKEEPER_SKIP_DOCTOR=0', async () => {
      process.env.VAULTKEEPER_SKIP_DOCTOR = '0'
      const mockVault = { setDevelopmentMode: vi.fn().mockResolvedValue(undefined) }
      mockInit.mockResolvedValue(mockVault)
      const { devModeCommand } = await import('../../../src/commands/dev-mode.js')
      await devModeCommand(['enable', '--script', '/path/to/script.sh'])
      expect(mockInit).toHaveBeenCalledWith({ skipDoctor: false })
    })
  })

  describe('--help flag', () => {
    it('should include --skip-doctor in help output', async () => {
      const { devModeCommand } = await import('../../../src/commands/dev-mode.js')
      await devModeCommand(['--help'])
      expect(stdoutOutput).toContain('--skip-doctor')
    })

    it('should include VAULTKEEPER_SKIP_DOCTOR env var in help output', async () => {
      const { devModeCommand } = await import('../../../src/commands/dev-mode.js')
      await devModeCommand(['--help'])
      expect(stdoutOutput).toContain('VAULTKEEPER_SKIP_DOCTOR')
    })
  })
})
