/**
 * UATs for help output and unknown command handling.
 */
import { describe, it, expect, afterEach } from 'vitest'
import { createCliTestEnv } from '@vaultkeeper/cli-test-helpers'
import type { CliTestEnv } from '@vaultkeeper/cli-test-helpers'

describe('help and usage', () => {
  let env: CliTestEnv | undefined

  afterEach(async () => {
    if (env !== undefined) {
      await env.cleanup()
      env = undefined
    }
  })

  it('should print full help to stdout and exit 0 when no arguments are given', async () => {
    // A bare invocation renders the identical help `--help` prints, so it is a
    // help request, not a usage error (issue #202, reversing #151): help goes
    // to stdout and the exit code is 0. Genuine misuse (unknown command/flag,
    // missing args) still exits 2 — see the cases below.
    env = await createCliTestEnv()
    const result = await env.run([])
    expect(result.exitCode).toBe(0)
    expect(result.stdout).toContain('Usage: vaultkeeper [--config-dir <path>] <command>')
    expect(result.stderr).toBe('')
  })

  it('should print help and exit 0 for --help', async () => {
    env = await createCliTestEnv()
    const result = await env.run(['--help'])
    expect(result.exitCode).toBe(0)
    expect(result.stdout).toContain('Usage: vaultkeeper [--config-dir <path>] <command>')
  })

  it('should print help and exit 0 for -h', async () => {
    env = await createCliTestEnv()
    const result = await env.run(['-h'])
    expect(result.exitCode).toBe(0)
    expect(result.stdout).toContain('Usage: vaultkeeper [--config-dir <path>] <command>')
  })

  it('should exit 2 and show error for unknown command', async () => {
    env = await createCliTestEnv()
    const result = await env.run(['not-a-real-command'])
    expect(result.exitCode).toBe(2)
    expect(result.stderr).toContain('Unknown command: not-a-real-command')
    expect(result.stdout).toContain('Usage: vaultkeeper [--config-dir <path>] <command>')
  })

  // Regression: issue #193 item 3 — an unknown TOP-LEVEL flag previously printed
  // only an error line with no Usage: block, unlike the unknown-command case and
  // every subcommand-level usage error. It must exit 2 AND print the Usage:
  // block (error on stderr, usage on stdout, matching unknown-command).
  it('should exit 2 with an error and a Usage: block for an unknown top-level flag', async () => {
    env = await createCliTestEnv()
    const result = await env.run(['--bogus'])
    expect(result.exitCode).toBe(2)
    expect(result.stderr).toContain("unknown option '--bogus'")
    expect(result.stdout).toContain('Usage: vaultkeeper [--config-dir <path>] <command>')
  })

  it('should print version and exit 0 for --version', async () => {
    env = await createCliTestEnv()
    const result = await env.run(['--version'])
    expect(result.exitCode).toBe(0)
    expect(result.stdout.trim()).toMatch(/^\d+\.\d+\.\d+/)
  })

  it('should print version and exit 0 for -V', async () => {
    env = await createCliTestEnv()
    const result = await env.run(['-V'])
    expect(result.exitCode).toBe(0)
    expect(result.stdout.trim()).toMatch(/^\d+\.\d+\.\d+/)
  })

  // Issue #202: `-v` (commonly guessed) is wired to the same version output.
  it('should print version and exit 0 for -v', async () => {
    env = await createCliTestEnv()
    const result = await env.run(['-v'])
    expect(result.exitCode).toBe(0)
    expect(result.stdout.trim()).toMatch(/^\d+\.\d+\.\d+/)
  })

  // Issue #202: --version must be listed in the top-level Global options so it
  // is discoverable from --help, not only by guessing.
  it('should list --version under Global options in --help', async () => {
    env = await createCliTestEnv()
    const result = await env.run(['--help'])
    expect(result.exitCode).toBe(0)
    expect(result.stdout).toContain('Global options:')
    expect(result.stdout).toContain('--version')
  })

  it('should list all expected commands in help output', async () => {
    env = await createCliTestEnv()
    const result = await env.run(['--help'])
    const commands = [
      'exec',
      'doctor',
      'approve',
      'dev-mode',
      'store',
      'delete',
      'config',
      'rotate-key',
      'revoke-key',
    ]
    for (const cmd of commands) {
      expect(result.stdout).toContain(cmd)
    }
  })
})
