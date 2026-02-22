import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'

// Capture mock fn references in the factory closure to avoid
// accessing class methods through vi.mocked(), which triggers
// @typescript-eslint/unbound-method on static class method types.
const mockDoctor = vi.fn()

vi.mock('vaultkeeper', () => ({
  VaultKeeper: {
    doctor: mockDoctor,
  },
}))

describe('doctorCommand', () => {
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

  describe('when system is ready', () => {
    it('should return 0', async () => {
      mockDoctor.mockResolvedValue({
        ready: true,
        checks: [{ name: 'keychain', status: 'ok' }],
        warnings: [],
        nextSteps: [],
      })
      const { doctorCommand } = await import('../../../src/commands/doctor.js')
      const code = await doctorCommand([])
      expect(code).toBe(0)
    })

    it('should write ready message to stdout', async () => {
      mockDoctor.mockResolvedValue({
        ready: true,
        checks: [{ name: 'keychain', status: 'ok' }],
        warnings: [],
        nextSteps: [],
      })
      const { doctorCommand } = await import('../../../src/commands/doctor.js')
      await doctorCommand([])
      expect(stdoutOutput).toContain('System ready.')
    })

    it('should display each check result with ✓ icon', async () => {
      mockDoctor.mockResolvedValue({
        ready: true,
        checks: [{ name: 'keychain', status: 'ok', version: '1.2.3' }],
        warnings: [],
        nextSteps: [],
      })
      const { doctorCommand } = await import('../../../src/commands/doctor.js')
      await doctorCommand([])
      expect(stdoutOutput).toContain('✓')
      expect(stdoutOutput).toContain('keychain')
      expect(stdoutOutput).toContain('1.2.3')
    })

    it('should display warnings when present', async () => {
      mockDoctor.mockResolvedValue({
        ready: true,
        checks: [],
        warnings: ['Keychain is locked'],
        nextSteps: [],
      })
      const { doctorCommand } = await import('../../../src/commands/doctor.js')
      await doctorCommand([])
      expect(stdoutOutput).toContain('Warnings:')
      expect(stdoutOutput).toContain('Keychain is locked')
    })
  })

  describe('when system is not ready', () => {
    it('should return 1', async () => {
      mockDoctor.mockResolvedValue({
        ready: false,
        checks: [{ name: 'keychain', status: 'error', reason: 'not available' }],
        warnings: [],
        nextSteps: ['Install keychain'],
      })
      const { doctorCommand } = await import('../../../src/commands/doctor.js')
      const code = await doctorCommand([])
      expect(code).toBe(1)
    })

    it('should display next steps', async () => {
      mockDoctor.mockResolvedValue({
        ready: false,
        checks: [{ name: 'keychain', status: 'error', reason: 'not available' }],
        warnings: [],
        nextSteps: ['Install keychain'],
      })
      const { doctorCommand } = await import('../../../src/commands/doctor.js')
      await doctorCommand([])
      expect(stdoutOutput).toContain('Next steps:')
      expect(stdoutOutput).toContain('Install keychain')
    })

    it('should display failed checks with ✗ icon', async () => {
      mockDoctor.mockResolvedValue({
        ready: false,
        checks: [{ name: 'keychain', status: 'error', reason: 'not available' }],
        warnings: [],
        nextSteps: [],
      })
      const { doctorCommand } = await import('../../../src/commands/doctor.js')
      await doctorCommand([])
      expect(stdoutOutput).toContain('✗')
      expect(stdoutOutput).toContain('not available')
    })
  })

  describe('when VaultKeeper.doctor() throws', () => {
    it('should return 1', async () => {
      mockDoctor.mockRejectedValue(new Error('doctor failed'))
      const { doctorCommand } = await import('../../../src/commands/doctor.js')
      const code = await doctorCommand([])
      expect(code).toBe(1)
    })

    it('should write formatted error to stderr', async () => {
      mockDoctor.mockRejectedValue(new Error('doctor failed'))
      const { doctorCommand } = await import('../../../src/commands/doctor.js')
      await doctorCommand([])
      expect(stderrOutput).toContain('doctor failed')
    })
  })
})
