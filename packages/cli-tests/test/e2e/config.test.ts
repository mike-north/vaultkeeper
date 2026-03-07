/**
 * UATs for the config init/show lifecycle.
 *
 * These tests verify the config command works with an isolated config dir
 * via VAULTKEEPER_CONFIG_DIR.
 */
import { describe, it, expect, afterEach } from 'vitest'
import * as fs from 'node:fs/promises'
import * as path from 'node:path'
import { createCliTestEnv } from '@vaultkeeper/cli-test-helpers'
import type { CliTestEnv } from '@vaultkeeper/cli-test-helpers'

describe('config command', () => {
  let env: CliTestEnv | undefined

  afterEach(async () => {
    if (env !== undefined) {
      await env.cleanup()
      env = undefined
    }
  })

  it('should show config and exit 0 when config.json exists', async () => {
    env = await createCliTestEnv()
    const result = await env.run(['config', 'show'])
    expect(result.exitCode).toBe(0)
    const parsed: unknown = JSON.parse(result.stdout)
    expect(parsed).toHaveProperty('version', 1)
    expect(parsed).toHaveProperty('backends')
  })

  it('should exit 1 for config init when config already exists', async () => {
    env = await createCliTestEnv()
    // createCliTestEnv already writes config.json
    const result = await env.run(['config', 'init'])
    expect(result.exitCode).toBe(1)
    expect(result.stderr).toContain('already exists')
  })

  it('should create config with config init when no config exists', async () => {
    env = await createCliTestEnv()
    // Remove the config.json that createCliTestEnv wrote
    await fs.rm(path.join(env.configDir, 'config.json'))
    const result = await env.run(['config', 'init'])
    expect(result.exitCode).toBe(0)
    expect(result.stdout).toContain('Config created at')
    // Verify the file was actually created
    const content = await fs.readFile(path.join(env.configDir, 'config.json'), 'utf8')
    const parsed: unknown = JSON.parse(content)
    expect(parsed).toHaveProperty('version', 1)
  })

  it('should exit 1 for config show when no config exists', async () => {
    env = await createCliTestEnv()
    // Remove the config.json
    await fs.rm(path.join(env.configDir, 'config.json'))
    const result = await env.run(['config', 'show'])
    expect(result.exitCode).toBe(1)
  })

  it('should exit 2 for config with no subcommand', async () => {
    env = await createCliTestEnv()
    const result = await env.run(['config'])
    expect(result.exitCode).toBe(2)
    expect(result.stderr).toContain('Usage: vaultkeeper config')
  })
})
