import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { deleteCommand } from '../../../src/commands/delete.js'

vi.mock('vaultkeeper', () => ({
  VaultKeeper: {
    init: vi.fn(),
  },
  BackendRegistry: {
    getTypes: vi.fn(() => []),
    create: vi.fn(),
  },
}))

describe('deleteCommand', () => {
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

  describe('--name flag validation', () => {
    it('should return 1 when --name is missing', async () => {
      const code = await deleteCommand([])
      expect(code).toBe(1)
    })

    it('should write error to stderr when --name is missing', async () => {
      await deleteCommand([])
      expect(stderrOutput).toContain('--name is required')
    })

    it('should include usage hint when --name is missing', async () => {
      await deleteCommand([])
      expect(stderrOutput).toContain('Usage:')
    })
  })
})
