import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { storeCommand } from '../../../src/commands/store.js'

const mockInit = vi.hoisted(() => vi.fn())

vi.mock('vaultkeeper', () => ({
  VaultKeeper: {
    init: mockInit,
  },
  BackendRegistry: {
    getTypes: vi.fn(() => []),
    create: vi.fn(),
  },
}))

describe('storeCommand', () => {
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

  describe('--name flag validation', () => {
    it('should return 2 when --name is missing', async () => {
      const code = await storeCommand([])
      expect(code).toBe(2)
    })

    it('should write error to stderr when --name is missing', async () => {
      await storeCommand([])
      expect(stderrOutput).toContain('--name is required')
    })

    it('should include usage hint when --name is missing', async () => {
      await storeCommand([])
      expect(stderrOutput).toContain('Usage:')
    })
  })

  describe('--help flag', () => {
    it('should include --skip-doctor in help output', async () => {
      await storeCommand(['--help'])
      expect(stdoutOutput).toContain('--skip-doctor')
    })

    it('should include VAULTKEEPER_SKIP_DOCTOR env var in help output', async () => {
      await storeCommand(['--help'])
      expect(stdoutOutput).toContain('VAULTKEEPER_SKIP_DOCTOR')
    })
  })
})
