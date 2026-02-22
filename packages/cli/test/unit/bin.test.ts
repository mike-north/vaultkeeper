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
    execFile(
      TSX_BIN,
      [BIN_PATH, ...args],
      { timeout: 15000 },
      (error, stdout, stderr) => {
        const exitCode =
          error !== null
            ? typeof error.code === 'number'
              ? error.code
              : 1
            : 0
        resolve({ stdout, stderr, exitCode })
      },
    )
  })
}

describe('bin.ts entry point', () => {
  it('should print help and exit 0 when no arguments are given', async () => {
    const result = await runCli([])
    expect(result.exitCode).toBe(0)
    expect(result.stdout).toContain('Usage: vaultkeeper <command>')
    expect(result.stdout).toContain('exec')
    expect(result.stdout).toContain('doctor')
  })

  it('should print help and exit 0 for --help', async () => {
    const result = await runCli(['--help'])
    expect(result.exitCode).toBe(0)
    expect(result.stdout).toContain('Usage: vaultkeeper <command>')
  })

  it('should print help and exit 0 for -h', async () => {
    const result = await runCli(['-h'])
    expect(result.exitCode).toBe(0)
    expect(result.stdout).toContain('Usage: vaultkeeper <command>')
  })

  it('should write an error to stderr and exit 1 for an unknown command', async () => {
    const result = await runCli(['not-a-real-command'])
    expect(result.exitCode).toBe(1)
    expect(result.stderr).toContain('Unknown command: not-a-real-command')
  })

  it('should include help text after an unknown command error', async () => {
    const result = await runCli(['totally-bogus'])
    expect(result.exitCode).toBe(1)
    expect(result.stdout).toContain('Usage: vaultkeeper <command>')
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
})
