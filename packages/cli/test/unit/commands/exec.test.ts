import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { execCommand } from '../../../src/commands/exec.js'
import { promptApproval } from '../../../src/approval.js'
import { readCachedToken } from '../../../src/cache.js'

const mockInit = vi.hoisted(() => vi.fn())

// A real IdentityMismatchError subclass so `.name`/`.message` format exactly as
// the CLI expects when it constructs and formats the mismatch error. Defined
// via vi.hoisted so it is initialized before the hoisted vi.mock factory runs.
// Each constructed instance is recorded so tests can assert the CLI populated
// previousHash/currentHash with the real hashes (not a placeholder).
const IdentityMismatchError = vi.hoisted(
  () =>
    class IdentityMismatchError extends Error {
      static readonly instances: IdentityMismatchError[] = []
      readonly previousHash: string
      readonly currentHash: string
      constructor(message: string, previousHash: string, currentHash: string) {
        super(message)
        this.name = 'IdentityMismatchError'
        this.previousHash = previousHash
        this.currentHash = currentHash
        IdentityMismatchError.instances.push(this)
      }
    },
)

vi.mock('vaultkeeper', () => ({
  VaultKeeper: {
    init: mockInit,
  },
  IdentityMismatchError,
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
    IdentityMismatchError.instances.length = 0
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
      const code = await execCommand([
        '--secret',
        'my-key',
        '--env',
        'MY_VAR',
        '--caller',
        '/path/to/script.sh',
      ])
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
      const code = await execCommand([
        '--secret',
        'my-key',
        '--env',
        'MY_VAR',
        '--caller',
        '/path/to/script.sh',
        '--',
      ])
      expect(code).toBe(2)
    })

    it('should write error message when command after -- is empty', async () => {
      await execCommand([
        '--secret',
        'my-key',
        '--env',
        'MY_VAR',
        '--caller',
        '/path/to/script.sh',
        '--',
      ])
      expect(stderrOutput).toContain('No command provided after --')
    })
  })

  describe('required flag validation', () => {
    it('should return 2 when --secret is missing', async () => {
      const code = await execCommand([
        '--env',
        'MY_VAR',
        '--caller',
        '/path/to/script.sh',
        '--',
        'echo',
        'hello',
      ])
      expect(code).toBe(2)
    })

    it('should return 2 when --env is missing', async () => {
      const code = await execCommand([
        '--secret',
        'my-key',
        '--caller',
        '/path/to/script.sh',
        '--',
        'echo',
        'hello',
      ])
      expect(code).toBe(2)
    })

    it('should return 2 when --caller is missing', async () => {
      const code = await execCommand([
        '--secret',
        'my-key',
        '--env',
        'MY_VAR',
        '--',
        'echo',
        'hello',
      ])
      expect(code).toBe(2)
    })

    it('should return 2 when all required flags are missing', async () => {
      const code = await execCommand(['--', 'echo', 'hello'])
      expect(code).toBe(2)
    })

    it('should write error message when required flags are missing', async () => {
      await execCommand([
        '--env',
        'MY_VAR',
        '--caller',
        '/path/to/script.sh',
        '--',
        'echo',
        'hello',
      ])
      expect(stderrOutput).toContain('--secret, --env, and --caller are required')
    })
  })

  describe('--skip-doctor flag', () => {
    it('should pass skipDoctor: false to VaultKeeper.init by default', async () => {
      // promptApproval returns false, so init will be called but the command exits at denial
      mockInit.mockResolvedValue({ setup: vi.fn(), authorize: vi.fn(), getSecret: vi.fn() })
      await execCommand([
        '--secret',
        'my-key',
        '--env',
        'MY_VAR',
        '--caller',
        '/path/to/script.sh',
        '--',
        'echo',
        'hello',
      ])
      expect(mockInit).toHaveBeenCalledWith({ skipDoctor: false })
    })

    it('should pass skipDoctor: true to VaultKeeper.init when --skip-doctor is set', async () => {
      mockInit.mockResolvedValue({ setup: vi.fn(), authorize: vi.fn(), getSecret: vi.fn() })
      await execCommand([
        '--skip-doctor',
        '--secret',
        'my-key',
        '--env',
        'MY_VAR',
        '--caller',
        '/path/to/script.sh',
        '--',
        'echo',
        'hello',
      ])
      expect(mockInit).toHaveBeenCalledWith({ skipDoctor: true })
    })

    it('should pass skipDoctor: true when VAULTKEEPER_SKIP_DOCTOR=1 env var is set', async () => {
      process.env.VAULTKEEPER_SKIP_DOCTOR = '1'
      mockInit.mockResolvedValue({ setup: vi.fn(), authorize: vi.fn(), getSecret: vi.fn() })
      await execCommand([
        '--secret',
        'my-key',
        '--env',
        'MY_VAR',
        '--caller',
        '/path/to/script.sh',
        '--',
        'echo',
        'hello',
      ])
      expect(mockInit).toHaveBeenCalledWith({ skipDoctor: true })
    })

    it('should not skip doctor when VAULTKEEPER_SKIP_DOCTOR=0', async () => {
      process.env.VAULTKEEPER_SKIP_DOCTOR = '0'
      mockInit.mockResolvedValue({ setup: vi.fn(), authorize: vi.fn(), getSecret: vi.fn() })
      await execCommand([
        '--secret',
        'my-key',
        '--env',
        'MY_VAR',
        '--caller',
        '/path/to/script.sh',
        '--',
        'echo',
        'hello',
      ])
      expect(mockInit).toHaveBeenCalledWith({ skipDoctor: false })
    })

    it('should not skip doctor when VAULTKEEPER_SKIP_DOCTOR=true (non-numeric)', async () => {
      process.env.VAULTKEEPER_SKIP_DOCTOR = 'true'
      mockInit.mockResolvedValue({ setup: vi.fn(), authorize: vi.fn(), getSecret: vi.fn() })
      await execCommand([
        '--secret',
        'my-key',
        '--env',
        'MY_VAR',
        '--caller',
        '/path/to/script.sh',
        '--',
        'echo',
        'hello',
      ])
      expect(mockInit).toHaveBeenCalledWith({ skipDoctor: false })
    })

    it('should not skip doctor when VAULTKEEPER_SKIP_DOCTOR is empty string', async () => {
      process.env.VAULTKEEPER_SKIP_DOCTOR = ''
      mockInit.mockResolvedValue({ setup: vi.fn(), authorize: vi.fn(), getSecret: vi.fn() })
      await execCommand([
        '--secret',
        'my-key',
        '--env',
        'MY_VAR',
        '--caller',
        '/path/to/script.sh',
        '--',
        'echo',
        'hello',
      ])
      expect(mockInit).toHaveBeenCalledWith({ skipDoctor: false })
    })
  })

  describe('trust gate', () => {
    const EXEC_ARGS = [
      '--secret',
      'my-key',
      '--env',
      'MY_VAR',
      '--caller',
      '/path/to/script.sh',
      '--',
      'echo',
      'hello',
    ]

    // Regression for review thread 3582165381: on a TOFU hash mismatch the CLI
    // must fail directly with an identity-mismatch error and re-approval
    // guidance, NOT prompt — setup() would reject the same hash conflict
    // regardless of the user's answer, so a prompt just wastes it.
    it('fails with an identity-mismatch error instead of prompting when the caller hash changed', async () => {
      const setup = vi.fn()
      const authorize = vi.fn()
      const getSecret = vi.fn()
      const checkExecutableTrust = vi.fn().mockResolvedValue({
        trusted: false,
        hashMismatch: true,
        hash: 'newhash',
        approvedHashes: ['oldhash'],
        reason: 'changed',
      })
      mockInit.mockResolvedValue({ checkExecutableTrust, setup, authorize, getSecret })

      const code = await execCommand(EXEC_ARGS)

      expect(code).toBe(1)
      expect(promptApproval).not.toHaveBeenCalled()
      expect(setup).not.toHaveBeenCalled()
      expect(authorize).not.toHaveBeenCalled()
      expect(stderrOutput).toContain('has changed since it was approved')
      expect(stderrOutput).toContain('vaultkeeper approve --script /path/to/script.sh')

      // Regression for review threads 3582262153 / 3582262187: the constructed
      // error carries the REAL hashes — the manifest-recorded approved hash and
      // the on-disk hash — never the old 'previously-approved' placeholder.
      const err = IdentityMismatchError.instances.at(-1)
      expect(err?.previousHash).toBe('oldhash')
      expect(err?.currentHash).toBe('newhash')
      expect(err?.previousHash).not.toBe('previously-approved')
    })

    // Regression for review thread 3582165347: a `--cache` hit must NOT bypass
    // the trust gate. A modified (hash-changed) caller with a previously cached
    // token must be refused, never silently riding the cached JWE.
    it('re-verifies caller trust on a --cache hit and refuses a modified caller', async () => {
      const setup = vi.fn()
      const authorize = vi.fn()
      const getSecret = vi.fn()
      const checkExecutableTrust = vi.fn().mockResolvedValue({
        trusted: false,
        hashMismatch: true,
        hash: 'newhash',
        approvedHashes: ['oldhash'],
        reason: 'changed',
      })
      mockInit.mockResolvedValue({ checkExecutableTrust, setup, authorize, getSecret })
      // A previously cached token exists — but the gate must run before it is used.
      vi.mocked(readCachedToken).mockResolvedValueOnce('cached.jwe.token')

      const code = await execCommand(['--cache', ...EXEC_ARGS])

      expect(code).not.toBe(0)
      // The cached token was never used to authorize or read the secret.
      expect(authorize).not.toHaveBeenCalled()
      expect(getSecret).not.toHaveBeenCalled()
      expect(stderrOutput).toContain('has changed since it was approved')
    })

    // Complement to the above: a trusted caller with a cache hit reuses the
    // cached token (no re-mint) and is not prompted.
    it('uses a cached token for a trusted caller without prompting or re-minting', async () => {
      const setup = vi.fn()
      const authorize = vi.fn().mockResolvedValue({ token: {}, vaultResponse: {} })
      const getSecret = vi.fn().mockReturnValue({
        read: (cb: (buf: Buffer) => void) => {
          cb(Buffer.from('s3cr3t'))
        },
      })
      const checkExecutableTrust = vi.fn().mockResolvedValue({
        trusted: true,
        hashMismatch: false,
        hash: 'goodhash',
        approvedHashes: ['goodhash'],
        reason: 'trusted',
      })
      mockInit.mockResolvedValue({ checkExecutableTrust, setup, authorize, getSecret })
      vi.mocked(readCachedToken).mockResolvedValueOnce('cached.jwe.token')

      const code = await execCommand(['--cache', ...EXEC_ARGS])

      expect(code).toBe(0)
      expect(promptApproval).not.toHaveBeenCalled()
      expect(setup).not.toHaveBeenCalled()
      expect(authorize).toHaveBeenCalledWith('cached.jwe.token')
      expect(stderrOutput).toContain('Trust: verified')
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
