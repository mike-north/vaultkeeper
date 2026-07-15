/**
 * Pins the CLI's exit-code taxonomy (0 success / 1 runtime error / 2 usage
 * error, established in issue #69) across a set of misuse cases that should
 * be treated equivalently, so a future change can't silently reintroduce a
 * straggler.
 *
 * Issue #118 closed two remaining gaps found against this taxonomy:
 *   - `store` with empty stdin previously returned 1 (runtime), inconsistent
 *     with `store --name ''` / missing `--name`, which return 2 (usage) for
 *     the same underlying problem: no usable input was given.
 *   - A bare invocation (no arguments) is NOT equivalent misuse to a
 *     misspelled subcommand — the former is the documented "print help"
 *     convenience (issue #69, still exit 0), the latter is a genuine usage
 *     error (exit 2). This suite pins both sides of that distinction so it
 *     is verified, not just assumed.
 *
 * @see https://github.com/mike-north/vaultkeeper/issues/69
 * @see https://github.com/mike-north/vaultkeeper/issues/118
 */
import { describe, it, expect, afterEach } from 'vitest'
import { createCliTestEnv } from '@vaultkeeper/cli-test-helpers'
import type { CliTestEnv } from '@vaultkeeper/cli-test-helpers'

describe('exit-code matrix (issue #118)', () => {
  let env: CliTestEnv | undefined

  afterEach(async () => {
    if (env !== undefined) {
      await env.cleanup()
      env = undefined
    }
  })

  it('a bare invocation (no arguments) exits 0 and prints help', async () => {
    env = await createCliTestEnv()
    const result = await env.run([])
    expect(result.exitCode).toBe(0)
  })

  it('a misspelled/unknown subcommand exits 2, unlike a bare invocation', async () => {
    env = await createCliTestEnv()
    const result = await env.run(['stroe'])
    expect(result.exitCode).toBe(2)
    expect(result.stderr).toContain('Unknown command')
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
  it('store with empty stdin exits 2 (usage error), matching missing/empty --name', async () => {
    env = await createCliTestEnv()
    const result = await env.runWithStdin(['store', '--name', 'test-secret', '--skip-doctor'], '')
    expect(result.exitCode).toBe(2)
    expect(result.stderr).toContain('No secret provided on stdin')
  })
})
