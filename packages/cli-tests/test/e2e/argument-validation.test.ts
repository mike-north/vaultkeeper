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

  // Issue #69, criterion 2: an empty/whitespace-only --name must exit 2 with
  // the same usage-error style as a missing flag, and must never persist a
  // secret. Repro: `store --name ""` previously reached VaultKeeper.store(),
  // which threw a generic VaultError with exit 1 instead of a usage error,
  // and the near-unreachable secret would still have been written for any
  // charset that passed the (nonexistent) validation.
  it('store should exit 2 for an empty --name and not persist a secret (regression: issue #69)', async () => {
    env = await createCliTestEnv()
    const result = await env.runWithStdin(['store', '--name', ''], 'some-secret')
    expect(result.exitCode).toBe(2)
    expect(result.stderr).toContain('--name must be non-empty')
    expect(result.stdout).not.toContain('stored successfully')
  })

  it('store should exit 2 for a whitespace-only --name', async () => {
    env = await createCliTestEnv()
    const result = await env.runWithStdin(['store', '--name', '   '], 'some-secret')
    expect(result.exitCode).toBe(2)
    expect(result.stderr).toContain('--name must be non-empty')
  })

  it('delete should exit 2 for an empty --name, consistent with store', async () => {
    env = await createCliTestEnv()
    const result = await env.run(['delete', '--name', ''])
    expect(result.exitCode).toBe(2)
    expect(result.stderr).toContain('--name must be non-empty')
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
