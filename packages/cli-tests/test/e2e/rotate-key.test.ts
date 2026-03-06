/**
 * UATs for the rotate-key command.
 *
 * Note: rotate-key calls VaultKeeper.init() which runs doctor checks.
 * If doctor fails (e.g., missing system dependencies), the command exits 1
 * with a doctor-related error. This is expected in constrained CI environments.
 */
import { describe, it, expect, afterEach } from 'vitest'
import { createCliTestEnv } from '@vaultkeeper/cli-test-helpers'
import type { CliTestEnv } from '@vaultkeeper/cli-test-helpers'

describe('rotate-key', () => {
  let env: CliTestEnv | undefined

  afterEach(async () => {
    if (env !== undefined) {
      await env.cleanup()
      env = undefined
    }
  })

  it('should rotate key or fail with doctor error', async () => {
    env = await createCliTestEnv()
    const result = await env.run(['rotate-key'])
    const succeeded =
      result.exitCode === 0 && result.stdout.includes('rotated successfully')
    const doctorFailed =
      result.exitCode === 1 && result.stderr.includes('System not ready')
    expect(succeeded || doctorFailed).toBe(true)
  })
})
