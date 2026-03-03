/**
 * UATs for the approve command.
 */
import { describe, it, expect, afterEach } from 'vitest'
import { createCliTestEnv } from '@vaultkeeper/cli-test-helpers'
import type { CliTestEnv } from '@vaultkeeper/cli-test-helpers'

describe('approve command', () => {
  let env: CliTestEnv | undefined

  afterEach(async () => {
    if (env !== undefined) {
      await env.cleanup()
      env = undefined
    }
  })

  it('should approve a script and exit 0', async () => {
    env = await createCliTestEnv()
    const result = await env.run(['approve', '--script', './test.sh'])
    expect(result.exitCode).toBe(0)
    expect(result.stdout).toContain('Script approved')
  })

})
