/**
 * UATs for the doctor command.
 *
 * Note: doctor output depends on the system environment (installed tools, etc).
 * These tests verify the command runs and produces structured check output.
 */
import { describe, it, expect, afterEach } from 'vitest'
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
})
