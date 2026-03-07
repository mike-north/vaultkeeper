import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'

// vi.hoisted ensures the mock factory can reference mockInit before imports are resolved.
const mockInit = vi.hoisted(() => vi.fn())

vi.mock('vaultkeeper', () => ({
  VaultKeeper: {
    init: mockInit,
  },
}))

describe('revokeKeyCommand', () => {
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

  describe('unknown flag handling', () => {
    it('should return 2 for unknown flags', async () => {
      const { revokeKeyCommand } = await import('../../../src/commands/revoke-key.js')
      const code = await revokeKeyCommand(['--bogus'])
      expect(code).toBe(2)
    })

    it('should write error message for unknown flags', async () => {
      const { revokeKeyCommand } = await import('../../../src/commands/revoke-key.js')
      await revokeKeyCommand(['--bogus'])
      expect(stderrOutput).toContain('Error:')
    })

    it('should print help after unknown flag error', async () => {
      const { revokeKeyCommand } = await import('../../../src/commands/revoke-key.js')
      await revokeKeyCommand(['--bogus'])
      expect(stdoutOutput).toContain('Usage: vaultkeeper revoke-key')
    })
  })

  describe('when VaultKeeper.init() throws', () => {
    it('should return 1', async () => {
      mockInit.mockRejectedValue(new Error('backend unavailable'))
      const { revokeKeyCommand } = await import('../../../src/commands/revoke-key.js')
      const code = await revokeKeyCommand([])
      expect(code).toBe(1)
    })

    it('should write formatted error to stderr', async () => {
      mockInit.mockRejectedValue(new Error('backend unavailable'))
      const { revokeKeyCommand } = await import('../../../src/commands/revoke-key.js')
      await revokeKeyCommand([])
      expect(stderrOutput).toContain('backend unavailable')
    })
  })

  describe('when VaultKeeper.init() succeeds but revokeKey() throws', () => {
    it('should return 1', async () => {
      const mockVault = { revokeKey: vi.fn().mockRejectedValue(new Error('revocation failed')) }
      mockInit.mockResolvedValue(mockVault)
      const { revokeKeyCommand } = await import('../../../src/commands/revoke-key.js')
      const code = await revokeKeyCommand([])
      expect(code).toBe(1)
    })

    it('should write formatted error to stderr', async () => {
      const mockVault = { revokeKey: vi.fn().mockRejectedValue(new Error('revocation failed')) }
      mockInit.mockResolvedValue(mockVault)
      const { revokeKeyCommand } = await import('../../../src/commands/revoke-key.js')
      await revokeKeyCommand([])
      expect(stderrOutput).toContain('revocation failed')
    })
  })

  describe('when revocation succeeds', () => {
    it('should return 0', async () => {
      const mockVault = { revokeKey: vi.fn().mockResolvedValue(undefined) }
      mockInit.mockResolvedValue(mockVault)
      const { revokeKeyCommand } = await import('../../../src/commands/revoke-key.js')
      const code = await revokeKeyCommand([])
      expect(code).toBe(0)
    })

    it('should write success message to stdout', async () => {
      const mockVault = { revokeKey: vi.fn().mockResolvedValue(undefined) }
      mockInit.mockResolvedValue(mockVault)
      const { revokeKeyCommand } = await import('../../../src/commands/revoke-key.js')
      await revokeKeyCommand([])
      expect(stdoutOutput).toContain('Key revoked successfully')
    })
  })

  describe('--skip-doctor flag', () => {
    it('should pass skipDoctor: false to VaultKeeper.init by default', async () => {
      const mockVault = { revokeKey: vi.fn().mockResolvedValue(undefined) }
      mockInit.mockResolvedValue(mockVault)
      const { revokeKeyCommand } = await import('../../../src/commands/revoke-key.js')
      await revokeKeyCommand([])
      expect(mockInit).toHaveBeenCalledWith({ skipDoctor: false })
    })

    it('should pass skipDoctor: true to VaultKeeper.init when --skip-doctor is set', async () => {
      const mockVault = { revokeKey: vi.fn().mockResolvedValue(undefined) }
      mockInit.mockResolvedValue(mockVault)
      const { revokeKeyCommand } = await import('../../../src/commands/revoke-key.js')
      await revokeKeyCommand(['--skip-doctor'])
      expect(mockInit).toHaveBeenCalledWith({ skipDoctor: true })
    })

    it('should pass skipDoctor: true when VAULTKEEPER_SKIP_DOCTOR=1 env var is set', async () => {
      process.env.VAULTKEEPER_SKIP_DOCTOR = '1'
      const mockVault = { revokeKey: vi.fn().mockResolvedValue(undefined) }
      mockInit.mockResolvedValue(mockVault)
      const { revokeKeyCommand } = await import('../../../src/commands/revoke-key.js')
      await revokeKeyCommand([])
      expect(mockInit).toHaveBeenCalledWith({ skipDoctor: true })
    })

    it('should not skip doctor when VAULTKEEPER_SKIP_DOCTOR=0', async () => {
      process.env.VAULTKEEPER_SKIP_DOCTOR = '0'
      const mockVault = { revokeKey: vi.fn().mockResolvedValue(undefined) }
      mockInit.mockResolvedValue(mockVault)
      const { revokeKeyCommand } = await import('../../../src/commands/revoke-key.js')
      await revokeKeyCommand([])
      expect(mockInit).toHaveBeenCalledWith({ skipDoctor: false })
    })
  })

  describe('--help flag', () => {
    it('should include --skip-doctor in help output', async () => {
      const { revokeKeyCommand } = await import('../../../src/commands/revoke-key.js')
      await revokeKeyCommand(['--help'])
      expect(stdoutOutput).toContain('--skip-doctor')
    })

    it('should include VAULTKEEPER_SKIP_DOCTOR env var in help output', async () => {
      const { revokeKeyCommand } = await import('../../../src/commands/revoke-key.js')
      await revokeKeyCommand(['--help'])
      expect(stdoutOutput).toContain('VAULTKEEPER_SKIP_DOCTOR')
    })
  })
})
