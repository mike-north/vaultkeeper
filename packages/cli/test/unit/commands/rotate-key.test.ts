import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'

// Capture mock fn reference in the factory closure to avoid
// accessing class methods through vi.mocked(), which triggers
// @typescript-eslint/unbound-method on static class method types.
const mockInit = vi.fn()

vi.mock('vaultkeeper', () => ({
  VaultKeeper: {
    init: mockInit,
  },
}))

describe('rotateKeyCommand', () => {
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
  })

  describe('when VaultKeeper.init() throws', () => {
    it('should return 1', async () => {
      mockInit.mockRejectedValue(new Error('backend unavailable'))
      const { rotateKeyCommand } = await import('../../../src/commands/rotate-key.js')
      const code = await rotateKeyCommand([])
      expect(code).toBe(1)
    })

    it('should write formatted error to stderr', async () => {
      mockInit.mockRejectedValue(new Error('backend unavailable'))
      const { rotateKeyCommand } = await import('../../../src/commands/rotate-key.js')
      await rotateKeyCommand([])
      expect(stderrOutput).toContain('backend unavailable')
    })

    it('should include error name in stderr output', async () => {
      class RotationError extends Error {
        constructor(message: string) {
          super(message)
          this.name = 'RotationError'
        }
      }
      mockInit.mockRejectedValue(new RotationError('key rotation failed'))
      const { rotateKeyCommand } = await import('../../../src/commands/rotate-key.js')
      await rotateKeyCommand([])
      expect(stderrOutput).toContain('RotationError')
    })
  })

  describe('when VaultKeeper.init() succeeds but rotateKey() throws', () => {
    it('should return 1', async () => {
      const mockVault = { rotateKey: vi.fn().mockRejectedValue(new Error('rotation failed')) }
      mockInit.mockResolvedValue(mockVault)
      const { rotateKeyCommand } = await import('../../../src/commands/rotate-key.js')
      const code = await rotateKeyCommand([])
      expect(code).toBe(1)
    })

    it('should write formatted error to stderr', async () => {
      const mockVault = { rotateKey: vi.fn().mockRejectedValue(new Error('rotation failed')) }
      mockInit.mockResolvedValue(mockVault)
      const { rotateKeyCommand } = await import('../../../src/commands/rotate-key.js')
      await rotateKeyCommand([])
      expect(stderrOutput).toContain('rotation failed')
    })
  })

  describe('when rotation succeeds', () => {
    it('should return 0', async () => {
      const mockVault = { rotateKey: vi.fn().mockResolvedValue(undefined) }
      mockInit.mockResolvedValue(mockVault)
      const { rotateKeyCommand } = await import('../../../src/commands/rotate-key.js')
      const code = await rotateKeyCommand([])
      expect(code).toBe(0)
    })

    it('should write success message to stdout', async () => {
      const mockVault = { rotateKey: vi.fn().mockResolvedValue(undefined) }
      mockInit.mockResolvedValue(mockVault)
      const { rotateKeyCommand } = await import('../../../src/commands/rotate-key.js')
      await rotateKeyCommand([])
      expect(stdoutOutput).toContain('Key rotated successfully')
    })
  })
})
