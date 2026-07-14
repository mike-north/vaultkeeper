import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { execCommand } from '../../../src/commands/exec.js'
import { promptApproval } from '../../../src/approval.js'
import { readCachedToken } from '../../../src/cache.js'

const configDir = '/tmp/vaultkeeper-test-config-dir'

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
  platformDefaultBackendType: vi.fn().mockReturnValue('file'),
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

/**
 * Default VaultKeeper mock for tests that drive execCommand end-to-end. It
 * includes checkExecutableTrust() — which execCommand now calls first, before
 * any prompt/cache/secret flow — returning a "pending" (never-approved, no
 * mismatch) status. With promptApproval mocked to decline, this deterministically
 * exercises the trust gate's "prompt → declined → Access denied" path rather than
 * short-circuiting on a missing-method TypeError.
 */
function pendingVaultMock(): {
  checkExecutableTrust: ReturnType<typeof vi.fn>
  setup: ReturnType<typeof vi.fn>
  authorize: ReturnType<typeof vi.fn>
  getSecret: ReturnType<typeof vi.fn>
} {
  return {
    checkExecutableTrust: vi.fn().mockResolvedValue({
      trusted: false,
      hashMismatch: false,
      hash: 'pending-hash',
      approvedHashes: [],
      reason: 'Executable not yet approved',
    }),
    setup: vi.fn(),
    authorize: vi.fn(),
    getSecret: vi.fn(),
  }
}

/**
 * Force `process.stdin.isTTY` to a fixed value for the duration of a test and
 * return a restore function. The trust gate only reaches the interactive prompt
 * on a TTY; on non-TTY stdin an untrusted caller fails with remediation instead.
 */
function forceStdinTTY(value: boolean): () => void {
  const original = Object.getOwnPropertyDescriptor(process.stdin, 'isTTY')
  Object.defineProperty(process.stdin, 'isTTY', { value, configurable: true })
  return () => {
    if (original === undefined) {
      Reflect.deleteProperty(process.stdin, 'isTTY')
    } else {
      Object.defineProperty(process.stdin, 'isTTY', original)
    }
  }
}

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
    delete process.env.VAULTKEEPER_YES
  })

  describe('-- separator validation', () => {
    it('should return 2 when -- separator is missing', async () => {
      const code = await execCommand(
        ['--secret', 'my-key', '--env', 'MY_VAR', '--caller', '/path/to/script.sh'],
        configDir,
      )
      expect(code).toBe(2)
    })

    it('should write error message when -- separator is missing', async () => {
      await execCommand(
        ['--secret', 'my-key', '--env', 'MY_VAR', '--caller', '/path/to/script.sh'],
        configDir,
      )
      expect(stderrOutput).toContain('Must provide command after --')
    })

    it('should include usage hint when -- separator is missing', async () => {
      await execCommand([], configDir)
      expect(stderrOutput).toContain('Usage: vaultkeeper exec')
    })
  })

  describe('command after -- validation', () => {
    it('should return 2 when command after -- is empty', async () => {
      const code = await execCommand(
        ['--secret', 'my-key', '--env', 'MY_VAR', '--caller', '/path/to/script.sh', '--'],
        configDir,
      )
      expect(code).toBe(2)
    })

    it('should write error message when command after -- is empty', async () => {
      await execCommand(
        ['--secret', 'my-key', '--env', 'MY_VAR', '--caller', '/path/to/script.sh', '--'],
        configDir,
      )
      expect(stderrOutput).toContain('No command provided after --')
    })
  })

  describe('required flag validation', () => {
    it('should return 2 when --secret is missing', async () => {
      const code = await execCommand(
        ['--env', 'MY_VAR', '--caller', '/path/to/script.sh', '--', 'echo', 'hello'],
        configDir,
      )
      expect(code).toBe(2)
    })

    it('should return 2 when --env is missing', async () => {
      const code = await execCommand(
        ['--secret', 'my-key', '--caller', '/path/to/script.sh', '--', 'echo', 'hello'],
        configDir,
      )
      expect(code).toBe(2)
    })

    it('should return 2 when --caller is missing', async () => {
      const code = await execCommand(
        ['--secret', 'my-key', '--env', 'MY_VAR', '--', 'echo', 'hello'],
        configDir,
      )
      expect(code).toBe(2)
    })

    it('should return 2 when all required flags are missing', async () => {
      const code = await execCommand(['--', 'echo', 'hello'], configDir)
      expect(code).toBe(2)
    })

    it('should write error message when required flags are missing', async () => {
      await execCommand(
        ['--env', 'MY_VAR', '--caller', '/path/to/script.sh', '--', 'echo', 'hello'],
        configDir,
      )
      expect(stderrOutput).toContain('--secret, --env, and --caller are required')
    })
  })

  describe('--skip-doctor flag', () => {
    // These drive the full command with a never-approved (pending) caller under
    // a simulated TTY, so the trust gate reaches promptApproval (mocked to
    // decline) and the command exits at "Access denied". Asserting the gate was
    // reached keeps these tests genuinely exercising the trust path — if the
    // default mock stopped providing checkExecutableTrust, execCommand would
    // throw before promptApproval and these assertions would fail. (On non-TTY
    // stdin an untrusted caller fails with remediation instead of prompting;
    // that path is covered by the "trust gate" tests below.)
    let restoreTTY: () => void = () => {
      /* replaced in beforeEach */
    }
    beforeEach(() => {
      restoreTTY = forceStdinTTY(true)
    })
    afterEach(() => {
      restoreTTY()
    })

    it('should pass skipDoctor: false to VaultKeeper.init by default', async () => {
      mockInit.mockResolvedValue(pendingVaultMock())
      await execCommand(
        [
          '--secret',
          'my-key',
          '--env',
          'MY_VAR',
          '--caller',
          '/path/to/script.sh',
          '--',
          'echo',
          'hello',
        ],
        configDir,
      )
      expect(mockInit).toHaveBeenCalledWith({ configDir, skipDoctor: false })
      expect(promptApproval).toHaveBeenCalled()
      expect(stderrOutput).toContain('Access denied by user.')
    })

    it('should pass skipDoctor: true to VaultKeeper.init when --skip-doctor is set', async () => {
      mockInit.mockResolvedValue(pendingVaultMock())
      await execCommand(
        [
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
        ],
        configDir,
      )
      expect(mockInit).toHaveBeenCalledWith({ configDir, skipDoctor: true })
      expect(promptApproval).toHaveBeenCalled()
    })

    it('should pass skipDoctor: true when VAULTKEEPER_SKIP_DOCTOR=1 env var is set', async () => {
      process.env.VAULTKEEPER_SKIP_DOCTOR = '1'
      mockInit.mockResolvedValue(pendingVaultMock())
      await execCommand(
        [
          '--secret',
          'my-key',
          '--env',
          'MY_VAR',
          '--caller',
          '/path/to/script.sh',
          '--',
          'echo',
          'hello',
        ],
        configDir,
      )
      expect(mockInit).toHaveBeenCalledWith({ configDir, skipDoctor: true })
      expect(promptApproval).toHaveBeenCalled()
    })

    it('should not skip doctor when VAULTKEEPER_SKIP_DOCTOR=0', async () => {
      process.env.VAULTKEEPER_SKIP_DOCTOR = '0'
      mockInit.mockResolvedValue(pendingVaultMock())
      await execCommand(
        [
          '--secret',
          'my-key',
          '--env',
          'MY_VAR',
          '--caller',
          '/path/to/script.sh',
          '--',
          'echo',
          'hello',
        ],
        configDir,
      )
      expect(mockInit).toHaveBeenCalledWith({ configDir, skipDoctor: false })
      expect(promptApproval).toHaveBeenCalled()
    })

    it('should not skip doctor when VAULTKEEPER_SKIP_DOCTOR=true (non-numeric)', async () => {
      process.env.VAULTKEEPER_SKIP_DOCTOR = 'true'
      mockInit.mockResolvedValue(pendingVaultMock())
      await execCommand(
        [
          '--secret',
          'my-key',
          '--env',
          'MY_VAR',
          '--caller',
          '/path/to/script.sh',
          '--',
          'echo',
          'hello',
        ],
        configDir,
      )
      expect(mockInit).toHaveBeenCalledWith({ configDir, skipDoctor: false })
      expect(promptApproval).toHaveBeenCalled()
    })

    it('should not skip doctor when VAULTKEEPER_SKIP_DOCTOR is empty string', async () => {
      process.env.VAULTKEEPER_SKIP_DOCTOR = ''
      mockInit.mockResolvedValue(pendingVaultMock())
      await execCommand(
        [
          '--secret',
          'my-key',
          '--env',
          'MY_VAR',
          '--caller',
          '/path/to/script.sh',
          '--',
          'echo',
          'hello',
        ],
        configDir,
      )
      expect(mockInit).toHaveBeenCalledWith({ configDir, skipDoctor: false })
      expect(promptApproval).toHaveBeenCalled()
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

      const code = await execCommand(EXEC_ARGS, configDir)

      expect(code).toBe(1)
      expect(promptApproval).not.toHaveBeenCalled()
      expect(setup).not.toHaveBeenCalled()
      expect(authorize).not.toHaveBeenCalled()
      expect(stderrOutput).toContain('has changed since it was approved')
      // Remediation shell-quotes the caller path (safe to copy/paste).
      expect(stderrOutput).toContain("vaultkeeper approve --script '/path/to/script.sh'")

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

      const code = await execCommand(['--cache', ...EXEC_ARGS], configDir)

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

      const code = await execCommand(['--cache', ...EXEC_ARGS], configDir)

      expect(code).toBe(0)
      expect(promptApproval).not.toHaveBeenCalled()
      expect(setup).not.toHaveBeenCalled()
      expect(authorize).toHaveBeenCalledWith('cached.jwe.token')
      expect(stderrOutput).toContain('Trust: verified')
    })

    // Issue #58, criterion 2: --yes approves a never-approved caller without a
    // prompt and records the approval the same way an interactive "y" would —
    // via setup(), which TOFU-records the caller hash on first encounter.
    it('approves an untrusted caller non-interactively with --yes and records trust via setup', async () => {
      const setup = vi.fn().mockResolvedValue('fresh.jwe')
      const authorize = vi.fn().mockResolvedValue({ token: {}, vaultResponse: {} })
      const getSecret = vi.fn().mockReturnValue({
        read: (cb: (buf: Buffer) => void) => {
          cb(Buffer.from('s3cr3t'))
        },
      })
      const checkExecutableTrust = vi.fn().mockResolvedValue({
        trusted: false,
        hashMismatch: false,
        hash: 'pending-hash',
        approvedHashes: [],
        reason: 'Executable not yet approved',
      })
      mockInit.mockResolvedValue({ checkExecutableTrust, setup, authorize, getSecret })

      const code = await execCommand(['--yes', ...EXEC_ARGS], configDir)

      expect(code).toBe(0)
      expect(promptApproval).not.toHaveBeenCalled()
      // Trust recording is delegated to setup() with the caller path, exactly as
      // the interactive "y" path does.
      expect(setup).toHaveBeenCalledWith('my-key', { executablePath: '/path/to/script.sh' })
      expect(stderrOutput).toContain('approved via --yes')
    })

    // Issue #58, criterion 2: VAULTKEEPER_YES=1 is equivalent to --yes.
    it('approves an untrusted caller non-interactively via VAULTKEEPER_YES=1', async () => {
      process.env.VAULTKEEPER_YES = '1'
      const setup = vi.fn().mockResolvedValue('fresh.jwe')
      const authorize = vi.fn().mockResolvedValue({ token: {}, vaultResponse: {} })
      const getSecret = vi.fn().mockReturnValue({
        read: (cb: (buf: Buffer) => void) => {
          cb(Buffer.from('s3cr3t'))
        },
      })
      const checkExecutableTrust = vi.fn().mockResolvedValue({
        trusted: false,
        hashMismatch: false,
        hash: 'pending-hash',
        approvedHashes: [],
        reason: 'Executable not yet approved',
      })
      mockInit.mockResolvedValue({ checkExecutableTrust, setup, authorize, getSecret })

      const code = await execCommand(EXEC_ARGS, configDir)

      expect(code).toBe(0)
      expect(promptApproval).not.toHaveBeenCalled()
      expect(setup).toHaveBeenCalledWith('my-key', { executablePath: '/path/to/script.sh' })
      expect(stderrOutput).toContain('approved via --yes')
    })

    // Regression for review thread 3582539153: --yes must record trust via
    // setup() even when a cached token exists. A just-approved (untrusted)
    // caller must not ride a cached token and skip recording — the cache is
    // reserved for callers that were ALREADY trusted.
    it('records trust via setup for a --yes caller even when a cached token exists', async () => {
      const setup = vi.fn().mockResolvedValue('fresh.jwe')
      const authorize = vi.fn().mockResolvedValue({ token: {}, vaultResponse: {} })
      const getSecret = vi.fn().mockReturnValue({
        read: (cb: (buf: Buffer) => void) => {
          cb(Buffer.from('s3cr3t'))
        },
      })
      const checkExecutableTrust = vi.fn().mockResolvedValue({
        trusted: false,
        hashMismatch: false,
        hash: 'pending-hash',
        approvedHashes: [],
        reason: 'Executable not yet approved',
      })
      mockInit.mockResolvedValue({ checkExecutableTrust, setup, authorize, getSecret })
      // A stale cached token exists — it must NOT be read or used for a caller
      // that is only being approved this run.
      vi.mocked(readCachedToken).mockResolvedValueOnce('cached.jwe.token')

      const code = await execCommand(['--cache', '--yes', ...EXEC_ARGS], configDir)

      expect(code).toBe(0)
      // The cache was not even consulted for a just-approved caller.
      expect(readCachedToken).not.toHaveBeenCalled()
      // setup() ran, recording the approval, and its fresh token was authorized.
      expect(setup).toHaveBeenCalledWith('my-key', { executablePath: '/path/to/script.sh' })
      expect(authorize).toHaveBeenCalledWith('fresh.jwe')
      expect(authorize).not.toHaveBeenCalledWith('cached.jwe.token')
    })

    // Issue #58, criterion 3: an untrusted caller on non-TTY stdin without --yes
    // fails, but the error tells the user exactly how to proceed (approve or --yes)
    // rather than the raw "requires interactive approval" message.
    it('fails with remediation guidance for an untrusted caller on non-TTY stdin', async () => {
      const restoreTTY = forceStdinTTY(false)
      try {
        const vault = pendingVaultMock()
        mockInit.mockResolvedValue(vault)

        const code = await execCommand(EXEC_ARGS, configDir)

        expect(code).toBe(1)
        expect(promptApproval).not.toHaveBeenCalled()
        expect(vault.setup).not.toHaveBeenCalled()
        // Remediation shell-quotes the caller path (safe to copy/paste).
        expect(stderrOutput).toContain("vaultkeeper approve --script '/path/to/script.sh'")
        expect(stderrOutput).toContain('--yes')
        expect(stderrOutput).toContain('VAULTKEEPER_YES=1')
      } finally {
        restoreTTY()
      }
    })
  })

  describe('--help flag', () => {
    it('should include --skip-doctor in help output', async () => {
      await execCommand(['--help'], configDir)
      expect(stdoutOutput).toContain('--skip-doctor')
    })

    it('should include VAULTKEEPER_SKIP_DOCTOR env var in help output', async () => {
      await execCommand(['--help'], configDir)
      expect(stdoutOutput).toContain('VAULTKEEPER_SKIP_DOCTOR')
    })

    // Issue #58, criterion 4: help documents the TTY requirement and both escape
    // hatches (--yes and VAULTKEEPER_YES), plus the approve alternative.
    it('documents the --yes flag and VAULTKEEPER_YES env var', async () => {
      await execCommand(['--help'], configDir)
      expect(stdoutOutput).toContain('--yes')
      expect(stdoutOutput).toContain('VAULTKEEPER_YES')
    })

    it('documents the TTY requirement and how to approve non-interactively', async () => {
      await execCommand(['--help'], configDir)
      expect(stdoutOutput).toContain('non-TTY')
      expect(stdoutOutput).toContain('vaultkeeper approve --script')
    })
  })
})
