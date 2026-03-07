/**
 * UATs for the dev-mode command.
 *
 * Note: dev-mode calls VaultKeeper.init() which runs doctor checks.
 * If doctor fails (e.g., missing system dependencies), the command exits 1
 * with a doctor-related error. This is expected in constrained CI environments.
 *
 * The TS CLI uses: `dev-mode enable --script <path>` / `dev-mode disable --script <path>`
 */
import { describe, it, expect, afterEach } from 'vitest'
import { createCliTestEnv } from '@vaultkeeper/cli-test-helpers'
import type { CliTestEnv } from '@vaultkeeper/cli-test-helpers'

describe('dev-mode', () => {
  let env: CliTestEnv | undefined

  afterEach(async () => {
    if (env !== undefined) {
      await env.cleanup()
      env = undefined
    }
  })

  it('should enable dev mode or fail with doctor error', async () => {
    env = await createCliTestEnv()
    const result = await env.run(['dev-mode', 'enable', '--script', '/tmp/test-script.sh'])
    const succeeded =
      result.exitCode === 0 && result.stdout.includes('enabled')
    const doctorFailed =
      result.exitCode === 1 && result.stderr.includes('System not ready')
    expect(succeeded || doctorFailed).toBe(true)
  })

  it('should show usage for missing arguments', async () => {
    env = await createCliTestEnv()
    const result = await env.run(['dev-mode'])
    expect(result.exitCode).toBe(2)
    expect(result.stderr).toContain('Usage')
  })
})
