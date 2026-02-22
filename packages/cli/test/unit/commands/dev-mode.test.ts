import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { devModeCommand } from '../../../src/commands/dev-mode.js'

vi.mock('vaultkeeper', () => ({
  VaultKeeper: {
    init: vi.fn(),
  },
}))

describe('devModeCommand', () => {
  let stderrOutput: string

  beforeEach(() => {
    stderrOutput = ''
    vi.spyOn(process.stderr, 'write').mockImplementation((chunk) => {
      stderrOutput += String(chunk)
      return true
    })
    vi.spyOn(process.stdout, 'write').mockImplementation(() => true)
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  describe('action validation', () => {
    it('should return 1 when no action is provided', async () => {
      const code = await devModeCommand(['--script', '/path/to/script.sh'])
      expect(code).toBe(1)
    })

    it('should return 1 for invalid action', async () => {
      const code = await devModeCommand(['invalid', '--script', '/path/to/script.sh'])
      expect(code).toBe(1)
    })

    it('should return 1 for action that is neither enable nor disable', async () => {
      const code = await devModeCommand(['toggle', '--script', '/path/to/script.sh'])
      expect(code).toBe(1)
    })

    it('should write usage to stderr for invalid action', async () => {
      await devModeCommand(['invalid', '--script', '/path/to/script.sh'])
      expect(stderrOutput).toContain('Usage: vaultkeeper dev-mode')
      expect(stderrOutput).toContain('<enable|disable>')
    })
  })

  describe('--script flag validation', () => {
    it('should return 1 when --script is missing with valid action', async () => {
      const code = await devModeCommand(['enable'])
      expect(code).toBe(1)
    })

    it('should return 1 when --script is missing with disable action', async () => {
      const code = await devModeCommand(['disable'])
      expect(code).toBe(1)
    })

    it('should write usage to stderr when --script is missing', async () => {
      await devModeCommand(['enable'])
      expect(stderrOutput).toContain('--script')
    })
  })

  describe('when both action and --script are missing', () => {
    it('should return 1 with no args', async () => {
      const code = await devModeCommand([])
      expect(code).toBe(1)
    })

    it('should write usage to stderr with no args', async () => {
      await devModeCommand([])
      expect(stderrOutput).toContain('Usage:')
    })
  })
})
