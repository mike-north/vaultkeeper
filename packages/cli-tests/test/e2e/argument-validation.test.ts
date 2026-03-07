/**
 * UATs for argument validation across commands.
 *
 * Verifies that commands exit 2 with usage hints when required flags are missing.
 * Exit code 2 follows the Unix convention for usage errors (matching clap/Rust CLI).
 */
import { describe, it, expect, afterEach } from 'vitest'
import { createCliTestEnv } from '@vaultkeeper/cli-test-helpers'
import type { CliTestEnv } from '@vaultkeeper/cli-test-helpers'

describe('argument validation', () => {
  let env: CliTestEnv | undefined

  afterEach(async () => {
    if (env !== undefined) {
      await env.cleanup()
      env = undefined
    }
  })

  it('store should exit 2 when --name is missing', async () => {
    env = await createCliTestEnv()
    const result = await env.runWithStdin(['store'], 'some-secret')
    expect(result.exitCode).toBe(2)
    expect(result.stderr).toContain('--name is required')
  })

  it('delete should exit 2 when --name is missing', async () => {
    env = await createCliTestEnv()
    const result = await env.run(['delete'])
    expect(result.exitCode).toBe(2)
    expect(result.stderr).toContain('--name is required')
  })

  it('exec should exit 2 when -- separator is missing', async () => {
    env = await createCliTestEnv()
    const result = await env.run(['exec'])
    expect(result.exitCode).toBe(2)
    expect(result.stderr).toContain('Must provide command after --')
  })

  it('dev-mode should exit 2 without proper arguments', async () => {
    env = await createCliTestEnv()
    const result = await env.run(['dev-mode'])
    expect(result.exitCode).toBe(2)
    expect(result.stderr).toContain('Usage: vaultkeeper dev-mode')
  })

  it('approve should exit 2 without --script', async () => {
    env = await createCliTestEnv()
    const result = await env.run(['approve'])
    expect(result.exitCode).toBe(2)
    expect(result.stderr).toContain('--script is required')
  })
})
