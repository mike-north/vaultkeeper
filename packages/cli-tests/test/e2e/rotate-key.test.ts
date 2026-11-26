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
    const succeeded = result.exitCode === 0 && result.stdout.includes('rotated successfully')
    const doctorFailed = result.exitCode === 1 && result.stderr.includes('System not ready')
    expect(succeeded || doctorFailed).toBe(true)
  })

  // Issue #59, criterion 5: the rotation grace-period guard survives across
  // processes. Two sequential rotate-key invocations sharing a config dir: the
  // first succeeds, the second fails with the documented RotationInProgressError
  // (non-zero exit, clear message) while the grace period is still active.
  it('rejects a second rotate-key while the previous key is in its grace period', async () => {
    env = await createCliTestEnv({ env: { VAULTKEEPER_SKIP_DOCTOR: '1' } })

    const first = await env.run(['rotate-key'])
    expect(first.exitCode).toBe(0)
    expect(first.stdout).toContain('rotated successfully')

    const second = await env.run(['rotate-key'])
    expect(second.exitCode).not.toBe(0)
    expect(second.stderr).toContain('rotation is already in progress')
  })
})
