/**
 * Self-tests for the CLI test environment factory.
 */
import { describe, it, expect, afterEach } from 'vitest'
import * as fs from 'node:fs/promises'
import * as path from 'node:path'
import { createCliTestEnv } from '../../src/index.js'
import type { CliTestEnv } from '../../src/index.js'

describe('createCliTestEnv', () => {
  let env: CliTestEnv | undefined

  afterEach(async () => {
    if (env !== undefined) {
      await env.cleanup()
      env = undefined
    }
  })

  it('should create an isolated temp directory with config.json', async () => {
    env = await createCliTestEnv()
    const configPath = path.join(env.configDir, 'config.json')
    const content = await fs.readFile(configPath, 'utf8')
    const parsed: unknown = JSON.parse(content)
    expect(parsed).toHaveProperty('version', 1)
  })

  it('should create a secrets subdirectory', async () => {
    env = await createCliTestEnv()
    const secretsDir = path.join(env.configDir, 'secrets')
    const stat = await fs.stat(secretsDir)
    expect(stat.isDirectory()).toBe(true)
  })

  it('should run --help and get exit 0', async () => {
    env = await createCliTestEnv()
    const result = await env.run(['--help'])
    expect(result.exitCode).toBe(0)
    expect(result.stdout).toContain('Usage: vaultkeeper <command>')
  })

  it('should set VAULTKEEPER_CONFIG_DIR in the subprocess', async () => {
    env = await createCliTestEnv()
    const result = await env.run(['config', 'show'])
    // config show should work because we wrote config.json
    expect(result.exitCode).toBe(0)
    expect(result.stdout).toContain('"version"')
  })

  it('should accept custom config', async () => {
    env = await createCliTestEnv({
      config: {
        version: 1,
        backends: [{ type: 'file', enabled: true }],
        keyRotation: { gracePeriodDays: 14 },
        defaults: { ttlMinutes: 120, trustTier: 2 },
      },
    })
    const result = await env.run(['config', 'show'])
    expect(result.exitCode).toBe(0)
    expect(result.stdout).toContain('"gracePeriodDays": 14')
  })

  it('should clean up the temp directory', async () => {
    const testEnv = await createCliTestEnv()
    const dir = testEnv.configDir
    await testEnv.cleanup()
    await expect(fs.access(dir)).rejects.toThrow()
    // Don't assign to env since already cleaned up
  })

  it('should pipe stdin data and not hang', async () => {
    env = await createCliTestEnv()
    // store requires --name and stdin data. The command may fail (doctor checks),
    // but what matters is that the process terminates (stdin was closed properly).
    const result = await env.runWithStdin(['store', '--name', 'test-secret'], 'my-secret-value')
    // Process terminated (did not hang waiting for stdin)
    expect(result.exitCode).toBeTypeOf('number')
    // Verify stdin data was actually piped — without --name, store would show
    // "--name is required" before reading stdin. With --name, any error must
    // come from a later stage (doctor or backend), proving stdin was consumed.
    expect(result.stderr).not.toContain('--name is required')
  })
})
