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

  it('should print help and exit 0 when no arguments are given', async () => {
    env = await createCliTestEnv()
    const result = await env.run([])
    expect(result.exitCode).toBe(0)
    expect(result.stdout).toContain('Usage: vaultkeeper <command>')
  })

  it('should print help and exit 0 for --help', async () => {
    env = await createCliTestEnv()
    const result = await env.run(['--help'])
    expect(result.exitCode).toBe(0)
    expect(result.stdout).toContain('Usage: vaultkeeper <command>')
  })

  it('should print help and exit 0 for -h', async () => {
    env = await createCliTestEnv()
    const result = await env.run(['-h'])
    expect(result.exitCode).toBe(0)
    expect(result.stdout).toContain('Usage: vaultkeeper <command>')
  })

  it('should exit 1 and show error for unknown command', async () => {
    env = await createCliTestEnv()
    const result = await env.run(['not-a-real-command'])
    expect(result.exitCode).toBe(1)
    expect(result.stderr).toContain('Unknown command: not-a-real-command')
    expect(result.stdout).toContain('Usage: vaultkeeper <command>')
  })

  it('should list all expected commands in help output', async () => {
    env = await createCliTestEnv()
    const result = await env.run(['--help'])
    const commands = ['exec', 'doctor', 'approve', 'dev-mode', 'store', 'delete', 'config', 'rotate-key']
    for (const cmd of commands) {
      expect(result.stdout).toContain(cmd)
    }
  })
})
