import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { execCommand } from '../../../src/commands/exec.js'

const mockInit = vi.hoisted(() => vi.fn())

vi.mock('vaultkeeper', () => ({
  VaultKeeper: {
    init: mockInit,
  },
}))

// Prevent any real approval prompts from blocking tests
vi.mock('../../../src/approval.js', () => ({
  promptApproval: vi.fn().mockResolvedValue(false),
}))

vi.mock('../../../src/cache.js', () => ({
  readCachedToken: vi.fn().mockResolvedValue(undefined),
  writeCachedToken: vi.fn().mockResolvedValue(undefined),
  invalidateCache: vi.fn().mockResolvedValue(undefined),
}))

describe('execCommand', () => {
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

  describe('-- separator validation', () => {
    it('should return 2 when -- separator is missing', async () => {
      const code = await execCommand(['--secret', 'my-key', '--env', 'MY_VAR', '--caller', '/path/to/script.sh'])
      expect(code).toBe(2)
    })

    it('should write error message when -- separator is missing', async () => {
      await execCommand(['--secret', 'my-key', '--env', 'MY_VAR', '--caller', '/path/to/script.sh'])
      expect(stderrOutput).toContain('Must provide command after --')
    })

    it('should include usage hint when -- separator is missing', async () => {
      await execCommand([])
      expect(stderrOutput).toContain('Usage: vaultkeeper exec')
    })
  })

  describe('command after -- validation', () => {
    it('should return 2 when command after -- is empty', async () => {
      const code = await execCommand(['--secret', 'my-key', '--env', 'MY_VAR', '--caller', '/path/to/script.sh', '--'])
      expect(code).toBe(2)
    })

    it('should write error message when command after -- is empty', async () => {
      await execCommand(['--secret', 'my-key', '--env', 'MY_VAR', '--caller', '/path/to/script.sh', '--'])
      expect(stderrOutput).toContain('No command provided after --')
    })
  })

  describe('required flag validation', () => {
    it('should return 2 when --secret is missing', async () => {
      const code = await execCommand(['--env', 'MY_VAR', '--caller', '/path/to/script.sh', '--', 'echo', 'hello'])
      expect(code).toBe(2)
    })

    it('should return 2 when --env is missing', async () => {
      const code = await execCommand(['--secret', 'my-key', '--caller', '/path/to/script.sh', '--', 'echo', 'hello'])
      expect(code).toBe(2)
    })

    it('should return 2 when --caller is missing', async () => {
      const code = await execCommand(['--secret', 'my-key', '--env', 'MY_VAR', '--', 'echo', 'hello'])
      expect(code).toBe(2)
    })

    it('should return 2 when all required flags are missing', async () => {
      const code = await execCommand(['--', 'echo', 'hello'])
      expect(code).toBe(2)
    })

    it('should write error message when required flags are missing', async () => {
      await execCommand(['--env', 'MY_VAR', '--caller', '/path/to/script.sh', '--', 'echo', 'hello'])
      expect(stderrOutput).toContain('--secret, --env, and --caller are required')
    })
  })

  describe('--skip-doctor flag', () => {
    it('should pass skipDoctor: false to VaultKeeper.init by default', async () => {
      // promptApproval returns false, so init will be called but the command exits at denial
      mockInit.mockResolvedValue({ setup: vi.fn(), authorize: vi.fn(), getSecret: vi.fn() })
      await execCommand([
        '--secret', 'my-key',
        '--env', 'MY_VAR',
        '--caller', '/path/to/script.sh',
        '--',
        'echo', 'hello',
      ])
      expect(mockInit).toHaveBeenCalledWith({ skipDoctor: false })
    })

    it('should pass skipDoctor: true to VaultKeeper.init when --skip-doctor is set', async () => {
      mockInit.mockResolvedValue({ setup: vi.fn(), authorize: vi.fn(), getSecret: vi.fn() })
      await execCommand([
        '--skip-doctor',
        '--secret', 'my-key',
        '--env', 'MY_VAR',
        '--caller', '/path/to/script.sh',
        '--',
        'echo', 'hello',
      ])
      expect(mockInit).toHaveBeenCalledWith({ skipDoctor: true })
    })

    it('should pass skipDoctor: true when VAULTKEEPER_SKIP_DOCTOR=1 env var is set', async () => {
      process.env.VAULTKEEPER_SKIP_DOCTOR = '1'
      mockInit.mockResolvedValue({ setup: vi.fn(), authorize: vi.fn(), getSecret: vi.fn() })
      await execCommand([
        '--secret', 'my-key',
        '--env', 'MY_VAR',
        '--caller', '/path/to/script.sh',
        '--',
        'echo', 'hello',
      ])
      expect(mockInit).toHaveBeenCalledWith({ skipDoctor: true })
    })

    it('should not skip doctor when VAULTKEEPER_SKIP_DOCTOR=0', async () => {
      process.env.VAULTKEEPER_SKIP_DOCTOR = '0'
      mockInit.mockResolvedValue({ setup: vi.fn(), authorize: vi.fn(), getSecret: vi.fn() })
      await execCommand([
        '--secret', 'my-key',
        '--env', 'MY_VAR',
        '--caller', '/path/to/script.sh',
        '--',
        'echo', 'hello',
      ])
      expect(mockInit).toHaveBeenCalledWith({ skipDoctor: false })
    })

    it('should not skip doctor when VAULTKEEPER_SKIP_DOCTOR=true (non-numeric)', async () => {
      process.env.VAULTKEEPER_SKIP_DOCTOR = 'true'
      mockInit.mockResolvedValue({ setup: vi.fn(), authorize: vi.fn(), getSecret: vi.fn() })
      await execCommand([
        '--secret', 'my-key',
        '--env', 'MY_VAR',
        '--caller', '/path/to/script.sh',
        '--',
        'echo', 'hello',
      ])
      expect(mockInit).toHaveBeenCalledWith({ skipDoctor: false })
    })

    it('should not skip doctor when VAULTKEEPER_SKIP_DOCTOR is empty string', async () => {
      process.env.VAULTKEEPER_SKIP_DOCTOR = ''
      mockInit.mockResolvedValue({ setup: vi.fn(), authorize: vi.fn(), getSecret: vi.fn() })
      await execCommand([
        '--secret', 'my-key',
        '--env', 'MY_VAR',
        '--caller', '/path/to/script.sh',
        '--',
        'echo', 'hello',
      ])
      expect(mockInit).toHaveBeenCalledWith({ skipDoctor: false })
    })
  })

  describe('--help flag', () => {
    it('should include --skip-doctor in help output', async () => {
      await execCommand(['--help'])
      expect(stdoutOutput).toContain('--skip-doctor')
    })

    it('should include VAULTKEEPER_SKIP_DOCTOR env var in help output', async () => {
      await execCommand(['--help'])
      expect(stdoutOutput).toContain('VAULTKEEPER_SKIP_DOCTOR')
    })
  })
})
