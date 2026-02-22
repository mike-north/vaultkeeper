import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { execCommand } from '../../../src/commands/exec.js'

vi.mock('vaultkeeper', () => ({
  VaultKeeper: {
    init: vi.fn(),
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

  beforeEach(() => {
    stderrOutput = ''
    vi.spyOn(process.stderr, 'write').mockImplementation((chunk) => {
      stderrOutput += String(chunk)
      return true
    })
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  describe('-- separator validation', () => {
    it('should return 1 when -- separator is missing', async () => {
      const code = await execCommand(['--secret', 'my-key', '--env', 'MY_VAR', '--caller', '/path/to/script.sh'])
      expect(code).toBe(1)
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
    it('should return 1 when command after -- is empty', async () => {
      const code = await execCommand(['--secret', 'my-key', '--env', 'MY_VAR', '--caller', '/path/to/script.sh', '--'])
      expect(code).toBe(1)
    })

    it('should write error message when command after -- is empty', async () => {
      await execCommand(['--secret', 'my-key', '--env', 'MY_VAR', '--caller', '/path/to/script.sh', '--'])
      expect(stderrOutput).toContain('No command provided after --')
    })
  })

  describe('required flag validation', () => {
    it('should return 1 when --secret is missing', async () => {
      const code = await execCommand(['--env', 'MY_VAR', '--caller', '/path/to/script.sh', '--', 'echo', 'hello'])
      expect(code).toBe(1)
    })

    it('should return 1 when --env is missing', async () => {
      const code = await execCommand(['--secret', 'my-key', '--caller', '/path/to/script.sh', '--', 'echo', 'hello'])
      expect(code).toBe(1)
    })

    it('should return 1 when --caller is missing', async () => {
      const code = await execCommand(['--secret', 'my-key', '--env', 'MY_VAR', '--', 'echo', 'hello'])
      expect(code).toBe(1)
    })

    it('should return 1 when all required flags are missing', async () => {
      const code = await execCommand(['--', 'echo', 'hello'])
      expect(code).toBe(1)
    })

    it('should write error message when required flags are missing', async () => {
      await execCommand(['--env', 'MY_VAR', '--caller', '/path/to/script.sh', '--', 'echo', 'hello'])
      expect(stderrOutput).toContain('--secret, --env, and --caller are required')
    })
  })
})
