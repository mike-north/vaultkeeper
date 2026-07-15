/**
 * Subprocess tests for the bin.ts entry point.
 *
 * bin.ts executes side effects at module scope (parseArgs, main()), so it
 * cannot be imported safely into the test process. These tests spawn a child
 * process via tsx to exercise the real entry-point behaviour end-to-end.
 */
import { describe, it, expect } from 'vitest'
import { execFile } from 'node:child_process'
import * as path from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))

const BIN_PATH = path.resolve(__dirname, '../../src/bin.ts')
const TSX_BIN = path.resolve(__dirname, '../../node_modules/.bin/tsx')

interface CliResult {
  stdout: string
  stderr: string
  exitCode: number
}

function runCli(args: string[]): Promise<CliResult> {
  return new Promise((resolve) => {
    execFile(TSX_BIN, [BIN_PATH, ...args], { timeout: 15000 }, (error, stdout, stderr) => {
      const exitCode = error !== null ? (typeof error.code === 'number' ? error.code : 1) : 0
      resolve({ stdout, stderr, exitCode })
    })
  })
}

describe('bin.ts entry point', () => {
  // Regression: issue #151 — a bare invocation previously printed help to
  // stdout and exited 0, which let `vaultkeeper && next_step` proceed as if a
  // command had succeeded. It is now a usage error: usage on stderr, exit 2.
  it('should print usage to stderr and exit 2 when no arguments are given', async () => {
    const result = await runCli([])
    expect(result.exitCode).toBe(2)
    expect(result.stderr).toContain('Usage: vaultkeeper [--config-dir <path>] <command>')
    expect(result.stderr).toContain('exec')
    expect(result.stderr).toContain('doctor')
  })

  it('should print help and exit 0 for --help', async () => {
    const result = await runCli(['--help'])
    expect(result.exitCode).toBe(0)
    expect(result.stdout).toContain('Usage: vaultkeeper [--config-dir <path>] <command>')
  })

  it('should print help and exit 0 for -h', async () => {
    const result = await runCli(['-h'])
    expect(result.exitCode).toBe(0)
    expect(result.stdout).toContain('Usage: vaultkeeper [--config-dir <path>] <command>')
  })

  it('should write an error to stderr and exit 2 for an unknown command', async () => {
    const result = await runCli(['not-a-real-command'])
    expect(result.exitCode).toBe(2)
    expect(result.stderr).toContain('Unknown command: not-a-real-command')
  })

  it('should include help text after an unknown command error', async () => {
    const result = await runCli(['totally-bogus'])
    expect(result.exitCode).toBe(2)
    expect(result.stdout).toContain('Usage: vaultkeeper [--config-dir <path>] <command>')
  })

  it('should list all known commands in the help output', async () => {
    const result = await runCli(['--help'])
    const knownCommands = [
      'exec',
      'doctor',
      'approve',
      'dev-mode',
      'store',
      'delete',
      'config',
      'rotate-key',
    ]
    for (const cmd of knownCommands) {
      expect(result.stdout).toContain(cmd)
    }
  })

  it('should exit non-zero when exec is called without required arguments', async () => {
    // exec requires --secret, --env, --caller, and a -- separator
    const result = await runCli(['exec'])
    expect(result.exitCode).not.toBe(0)
  })

  describe('--version flag', () => {
    it('should print the package version and exit 0 for --version', async () => {
      const result = await runCli(['--version'])
      expect(result.exitCode).toBe(0)
      // Version string matches semver pattern (e.g. "0.1.4")
      expect(result.stdout.trim()).toMatch(/^\d+\.\d+\.\d+/)
    })

    it('should print the package version and exit 0 for -V', async () => {
      const result = await runCli(['-V'])
      expect(result.exitCode).toBe(0)
      expect(result.stdout.trim()).toMatch(/^\d+\.\d+\.\d+/)
    })
  })

  describe('per-subcommand --help', () => {
    it('should print usage and exit 0 for exec --help', async () => {
      const result = await runCli(['exec', '--help'])
      expect(result.exitCode).toBe(0)
      expect(result.stdout).toContain('Usage: vaultkeeper exec')
    })

    it('should print usage and exit 0 for exec -h', async () => {
      const result = await runCli(['exec', '-h'])
      expect(result.exitCode).toBe(0)
      expect(result.stdout).toContain('Usage: vaultkeeper exec')
    })

    it('should print usage and exit 0 for config --help', async () => {
      const result = await runCli(['config', '--help'])
      expect(result.exitCode).toBe(0)
      expect(result.stdout).toContain('Usage: vaultkeeper config')
    })

    it('should print usage and exit 0 for rotate-key --help', async () => {
      const result = await runCli(['rotate-key', '--help'])
      expect(result.exitCode).toBe(0)
      expect(result.stdout).toContain('Usage: vaultkeeper rotate-key')
    })

    it('should print usage and exit 0 for revoke-key --help', async () => {
      const result = await runCli(['revoke-key', '--help'])
      expect(result.exitCode).toBe(0)
      expect(result.stdout).toContain('Usage: vaultkeeper revoke-key')
    })

    it('should print usage and exit 0 for store --help', async () => {
      const result = await runCli(['store', '--help'])
      expect(result.exitCode).toBe(0)
      expect(result.stdout).toContain('Usage: echo "secret" | vaultkeeper store')
    })

    it('should print usage and exit 0 for delete --help', async () => {
      const result = await runCli(['delete', '--help'])
      expect(result.exitCode).toBe(0)
      expect(result.stdout).toContain('Usage: vaultkeeper delete')
    })

    it('should print usage and exit 0 for dev-mode --help', async () => {
      const result = await runCli(['dev-mode', '--help'])
      expect(result.exitCode).toBe(0)
      expect(result.stdout).toContain('Usage: vaultkeeper dev-mode')
    })

    it('should print usage and exit 0 for approve --help', async () => {
      const result = await runCli(['approve', '--help'])
      expect(result.exitCode).toBe(0)
      expect(result.stdout).toContain('Usage: vaultkeeper approve')
    })

    it('should print usage and exit 0 for doctor --help', async () => {
      const result = await runCli(['doctor', '--help'])
      expect(result.exitCode).toBe(0)
      expect(result.stdout).toContain('Usage: vaultkeeper doctor')
    })

    // Regression: issue #69 — 'config init --help' and 'config show --help'
    // previously printed the parent 'config' help (the top-level --help check
    // in configCommand ran before subcommand dispatch and matched any --help
    // anywhere in args).
    it('should print init-specific usage and exit 0 for config init --help', async () => {
      const result = await runCli(['config', 'init', '--help'])
      expect(result.exitCode).toBe(0)
      expect(result.stdout).toContain('Usage: vaultkeeper config init')
      expect(result.stdout).not.toContain('Usage: vaultkeeper config <subcommand>')
    })

    it('should print show-specific usage and exit 0 for config show --help', async () => {
      const result = await runCli(['config', 'show', '--help'])
      expect(result.exitCode).toBe(0)
      expect(result.stdout).toContain('Usage: vaultkeeper config show')
      expect(result.stdout).not.toContain('Usage: vaultkeeper config <subcommand>')
    })

    // Issue #69, criterion 5: exec --help includes a worked --caller example.
    it('should include a worked --caller example in exec --help', async () => {
      const result = await runCli(['exec', '--help'])
      expect(result.exitCode).toBe(0)
      expect(result.stdout).toContain('Example')
      expect(result.stdout).toContain('--caller')
      // The example must show a concrete path, not just the flag description.
      expect(result.stdout).toMatch(/--caller\s+\.\/[\w.-]+/)
    })
  })

  // Issue #69, criterion 1: a documented exit-code taxonomy (0/1/2) applied
  // uniformly. Unknown subcommand, unknown option at any level, missing
  // required flag, and invalid flag value all exit 2; runtime failures exit 1.
  describe('exit code 2 for usage errors', () => {
    it('should exit 2 for unknown command', async () => {
      const result = await runCli(['unknown-command-xyz'])
      expect(result.exitCode).toBe(2)
    })

    // Named regression for issue #69's core repro: a typo'd top-level flag
    // previously fell through to the "no command given" branch and printed
    // help with exit 0 — silently breaking scripts that check the exit code.
    it('should exit 2 for an unknown top-level flag (regression: issue #69, vaultkeeper --bogus previously exited 0)', async () => {
      const result = await runCli(['--bogus'])
      expect(result.exitCode).toBe(2)
      expect(result.stderr).toContain("unknown option '--bogus'")
    })

    it('should exit 2 for an unknown short top-level flag', async () => {
      const result = await runCli(['-x'])
      expect(result.exitCode).toBe(2)
    })

    it('should exit 2 for rotate-key with unknown flag', async () => {
      const result = await runCli(['rotate-key', '--bogus'])
      expect(result.exitCode).toBe(2)
    })

    it('should exit 2 for revoke-key with unknown flag', async () => {
      const result = await runCli(['revoke-key', '--bogus'])
      expect(result.exitCode).toBe(2)
    })

    // Regression: issue #69 — store/delete/exec/approve/dev-mode previously
    // called parseArgs({ strict: true }) unguarded; an unrecognized flag threw
    // synchronously and propagated uncaught to bin.ts's fatal-error handler,
    // which exits 1 instead of the usage-error exit code 2.
    it('should exit 2 for store with unknown flag', async () => {
      const result = await runCli(['store', '--bogus', 'x'])
      expect(result.exitCode).toBe(2)
    })

    it('should exit 2 for delete with unknown flag', async () => {
      const result = await runCli(['delete', '--bogus', 'x'])
      expect(result.exitCode).toBe(2)
    })

    it('should exit 2 for exec with unknown flag', async () => {
      const result = await runCli(['exec', '--bogus', 'x', '--', 'echo', 'hi'])
      expect(result.exitCode).toBe(2)
    })

    it('should exit 2 for approve with unknown flag', async () => {
      const result = await runCli(['approve', '--bogus', 'x'])
      expect(result.exitCode).toBe(2)
    })

    it('should exit 2 for dev-mode with unknown flag', async () => {
      const result = await runCli(['dev-mode', 'enable', '--bogus', 'x'])
      expect(result.exitCode).toBe(2)
    })

    // Regression: issue #69 — doctor never parsed its own args, so any
    // unrecognized flag was silently ignored and the real checks ran,
    // potentially exiting 0 for a typo'd flag.
    it('should exit 2 for doctor with unknown flag', async () => {
      const result = await runCli(['doctor', '--bogus'])
      expect(result.exitCode).toBe(2)
    })

    it('should exit 2 for config init with unknown flag', async () => {
      const result = await runCli(['config', 'init', '--bogus'])
      expect(result.exitCode).toBe(2)
    })

    it('should exit 2 for config show with unknown flag', async () => {
      const result = await runCli(['config', 'show', '--bogus'])
      expect(result.exitCode).toBe(2)
    })
  })

  // Issue #69, criterion 2: store rejects empty/whitespace-only --name with
  // exit 2 and the same error style as a missing flag. Safe to test without
  // an isolated config dir — the check runs before any backend I/O.
  describe('store --name validation', () => {
    it('should exit 2 for an empty --name, not silently succeed', async () => {
      const result = await runCli(['store', '--name', '', '--skip-doctor'])
      expect(result.exitCode).toBe(2)
      expect(result.stderr).toContain('--name must be non-empty')
    })

    it('should exit 2 for a whitespace-only --name', async () => {
      const result = await runCli(['store', '--name', '   ', '--skip-doctor'])
      expect(result.exitCode).toBe(2)
      expect(result.stderr).toContain('--name must be non-empty')
    })

    it('should document allowed --name characters in --help', async () => {
      const result = await runCli(['store', '--help'])
      expect(result.exitCode).toBe(0)
      expect(result.stdout).toMatch(/letters, digits/)
    })
  })

  // Regression (PR #95 review): exec's --secret/--env/--caller each had a
  // different, wrong exit code for an empty value — --secret exited 1 (a
  // VaultError from deep inside the vault), --caller exited 1 (a
  // FilesystemError from resolving '' to the current directory), and --env
  // exited 0 (silently injected the secret into an unusable '' env key and
  // ran the wrapped command anyway). All three must now exit 2, consistent
  // with store/delete's --name validation.
  describe('exec flag value validation', () => {
    it('should exit 2 for an empty --secret, not the deep VaultError exit 1', async () => {
      const result = await runCli([
        'exec',
        '--secret',
        '',
        '--env',
        'FOO',
        '--caller',
        './x',
        '--skip-doctor',
        '--',
        'echo',
        'hi',
      ])
      expect(result.exitCode).toBe(2)
      expect(result.stderr).toContain('must not be empty or whitespace-only')
    })

    it('should exit 2 for an empty --env, not silently succeed', async () => {
      const result = await runCli([
        'exec',
        '--secret',
        'my-key',
        '--env',
        '',
        '--caller',
        './x',
        '--skip-doctor',
        '--',
        'echo',
        'hi',
      ])
      expect(result.exitCode).toBe(2)
      expect(result.stdout).not.toContain('hi')
    })

    it('should exit 2 for an empty --caller, not the deep FilesystemError exit 1', async () => {
      const result = await runCli([
        'exec',
        '--secret',
        'my-key',
        '--env',
        'FOO',
        '--caller',
        '',
        '--skip-doctor',
        '--',
        'echo',
        'hi',
      ])
      expect(result.exitCode).toBe(2)
    })
  })
})
