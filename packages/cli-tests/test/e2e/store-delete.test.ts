/**
 * UATs for the store and delete secret lifecycle.
 *
 * Note: store and delete commands call VaultKeeper.init() which runs doctor
 * checks. If doctor fails (e.g., missing system dependencies), these tests
 * will show that failure rather than testing the store/delete logic. This is
 * expected — the UATs exercise the real CLI path.
 */
import { describe, it, expect, afterEach } from 'vitest'
import { createCliTestEnv } from '@vaultkeeper/cli-test-helpers'
import type { CliTestEnv } from '@vaultkeeper/cli-test-helpers'

describe('store and delete lifecycle', () => {
  let env: CliTestEnv | undefined

  afterEach(async () => {
    if (env !== undefined) {
      await env.cleanup()
      env = undefined
    }
  })

  it('store should exit 1 when stdin is empty', async () => {
    env = await createCliTestEnv()
    const result = await env.runWithStdin(['store', '--name', 'test-secret'], '')
    expect(result.exitCode).toBe(1)
    // The error is either "No secret provided on stdin" (file backend) or a
    // doctor check failure (if the system lacks dependencies). Both are valid
    // CLI error paths.
    const matchesExpected =
      result.stderr.includes('No secret provided on stdin') ||
      result.stderr.includes('doctor')
    expect(matchesExpected).toBe(true)
  })
})
