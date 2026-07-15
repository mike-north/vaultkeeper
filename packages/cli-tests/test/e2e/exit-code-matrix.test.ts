/**
 * Pins the CLI's exit-code taxonomy across the full matrix of invocation
 * outcomes, so a future change can't silently reintroduce a straggler.
 *
 * Convention (documented in packages/cli/src/bin.ts):
 *   0 — success
 *   1 — a valid invocation that failed at runtime (e.g. SecretNotFoundError)
 *   2 — a bad invocation: usage / argument-validation error
 *
 * History:
 *   - Issue #69 established the taxonomy and fixed bad-flag stragglers.
 *   - Issue #118 normalized empty-stdin `store` from 1 → 2.
 *   - Issue #151 normalized a bare invocation (no subcommand) from 0 → 2:
 *     printing help with exit 0 let `vaultkeeper && next_step` proceed as if a
 *     command had succeeded. A bare invocation is a bad invocation, like an
 *     unknown command, and now exits 2 with usage on stderr. An explicit
 *     `--help` / `-h` is still a successful usage request (exit 0, stdout).
 *
 * @see https://github.com/mike-north/vaultkeeper/issues/69
 * @see https://github.com/mike-north/vaultkeeper/issues/118
 * @see https://github.com/mike-north/vaultkeeper/issues/151
 */
import { describe, it, expect, afterEach } from 'vitest'
import { createCliTestEnv } from '@vaultkeeper/cli-test-helpers'
import type { CliTestEnv } from '@vaultkeeper/cli-test-helpers'

describe('exit-code matrix', () => {
  let env: CliTestEnv | undefined

  afterEach(async () => {
    if (env !== undefined) {
      await env.cleanup()
      env = undefined
    }
  })

  // --- 2: bad invocation (usage / validation) ---

  it('an unknown subcommand exits 2 with usage', async () => {
    env = await createCliTestEnv()
    const result = await env.run(['stroe'])
    expect(result.exitCode).toBe(2)
    expect(result.stderr).toContain('Unknown command')
    expect(result.stdout).toContain('Usage: vaultkeeper [--config-dir <path>] <command>')
  })

  it('an unknown flag exits 2 (usage error)', async () => {
    env = await createCliTestEnv()
    const result = await env.runWithStdin(['store', '--bogus'], 'sk-live-abc123')
    expect(result.exitCode).toBe(2)
    expect(result.stderr).toContain('Usage:')
  })

  it('store with a missing --name exits 2 (usage error)', async () => {
    env = await createCliTestEnv()
    const result = await env.runWithStdin(['store', '--skip-doctor'], 'sk-live-abc123')
    expect(result.exitCode).toBe(2)
  })

  it('store with an empty --name exits 2 (usage error)', async () => {
    env = await createCliTestEnv()
    const result = await env.runWithStdin(
      ['store', '--name', '', '--skip-doctor'],
      'sk-live-abc123',
    )
    expect(result.exitCode).toBe(2)
  })

  // Regression: issue #118 — this previously exited 1, inconsistent with the
  // two cases above for the same class of misuse (no usable input given).
  it('store with empty stdin exits 2 with a usage hint', async () => {
    env = await createCliTestEnv()
    const result = await env.runWithStdin(['store', '--name', 'test-secret', '--skip-doctor'], '')
    expect(result.exitCode).toBe(2)
    expect(result.stderr).toContain('No secret provided on stdin')
    expect(result.stderr).toContain('Usage:')
  })

  // Regression: issue #151 — a bare invocation previously exited 0, which let
  // `vaultkeeper && next_step` proceed as if a command had succeeded.
  it('a bare invocation (no arguments) exits 2 with usage on stderr', async () => {
    env = await createCliTestEnv()
    const result = await env.run([])
    expect(result.exitCode).toBe(2)
    expect(result.stderr).toContain('Usage: vaultkeeper [--config-dir <path>] <command>')
  })

  // --- 1: valid invocation that failed at runtime ---

  it('deleting a secret that does not exist exits 1 (runtime error)', async () => {
    env = await createCliTestEnv({ env: { VAULTKEEPER_SKIP_DOCTOR: '1' } })
    const result = await env.run(['delete', '--name', 'does-not-exist'])
    expect(result.exitCode).toBe(1)
    expect(result.stderr).toContain('not found')
  })

  // --- 0: success ---

  it('a successful store exits 0', async () => {
    env = await createCliTestEnv({ env: { VAULTKEEPER_SKIP_DOCTOR: '1' } })
    const result = await env.runWithStdin(['store', '--name', 'FOO'], 'sk-live-abc123')
    expect(result.exitCode).toBe(0)
    expect(result.stdout).toContain('stored successfully')
  })
})
