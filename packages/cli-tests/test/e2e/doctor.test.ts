/**
 * UATs for the doctor command.
 *
 * Note: doctor output depends on the system environment (installed tools, etc).
 * These tests verify the command runs and produces structured check output.
 */
import { describe, it, expect, afterEach } from 'vitest'
import * as fs from 'node:fs/promises'
import * as path from 'node:path'
import { createCliTestEnv } from '@vaultkeeper/cli-test-helpers'
import type { CliTestEnv } from '@vaultkeeper/cli-test-helpers'

describe('doctor command', () => {
  let env: CliTestEnv | undefined

  afterEach(async () => {
    if (env !== undefined) {
      await env.cleanup()
      env = undefined
    }
  })

  it('should run and produce check output', async () => {
    env = await createCliTestEnv()
    const result = await env.run(['doctor'])
    // Doctor may exit 0 (all checks pass) or 1 (some checks fail)
    // depending on the environment. We just verify it runs and produces output.
    expect(result.exitCode === 0 || result.exitCode === 1).toBe(true)
    // Output should contain check markers (✓ or ✗)
    const hasChecks = result.stdout.includes('✓') || result.stdout.includes('✗')
    expect(hasChecks).toBe(true)
  })

  // Repro from issue #68: with a corrupt config.json, doctor previously
  // never touched the config and reported "System ready." with exit 0. It
  // must now report a failing "config" check with the parse error and file
  // path, and exit non-zero.
  it('should report a failing config check and exit non-zero for corrupt config.json (issue #68 repro)', async () => {
    env = await createCliTestEnv()
    await fs.writeFile(path.join(env.configDir, 'config.json'), '{ bad json', 'utf8')
    const result = await env.run(['doctor'])
    expect(result.exitCode).not.toBe(0)
    expect(result.stdout).toContain('✗')
    expect(result.stdout).toContain('config')
    expect(result.stdout).toContain(path.join(env.configDir, 'config.json'))
    expect(result.stdout).toMatch(/line \d+, column \d+/)
    expect(result.stdout).toContain('vaultkeeper config init')
    expect(result.stdout).not.toContain('System ready.')
  })

  it('should report a failing config check for a structurally invalid config.json', async () => {
    env = await createCliTestEnv()
    await fs.writeFile(
      path.join(env.configDir, 'config.json'),
      JSON.stringify({ version: 99 }),
      'utf8',
    )
    const result = await env.run(['doctor'])
    expect(result.exitCode).not.toBe(0)
    expect(result.stdout).toContain('config')
    expect(result.stdout).toContain('version must be 1')
  })

  // No-config story (issue #68): doctor falls back to the default backend and
  // says so, uniformly with store/delete/exec/config show, rather than
  // silently defaulting or erroring. Issue #98: that default is the safe file
  // backend, and the hint spells out --backend.
  it('should report a default-backend message naming the file backend when no config file exists', async () => {
    env = await createCliTestEnv()
    await fs.rm(path.join(env.configDir, 'config.json'))
    const result = await env.run(['doctor'])
    expect(result.stderr).toContain('No config file found')
    expect(result.stderr).toContain('using the default backend (file)')
    expect(result.stderr).toContain('vaultkeeper config init --backend file')
  })
})
