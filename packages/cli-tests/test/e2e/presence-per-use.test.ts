/**
 * UATs for `--require-presence-per-use` refusal against a non-qualifying
 * backend (issue #122).
 *
 * The default `file` backend is not presence-per-use capable, so every
 * backend-touching command run with `--require-presence-per-use` must fail with
 * a `NotCapableError` (exit 1) whose message names qualifying backends — before
 * any credential is touched. The enforcement lives in the shared VaultKeeper
 * access path, so all commands behave identically.
 *
 * @see https://github.com/mike-north/vaultkeeper/issues/122
 */
import { describe, it, expect, afterEach } from 'vitest'
import * as process from 'node:process'
import { createCliTestEnv } from '@vaultkeeper/cli-test-helpers'
import type { CliTestEnv } from '@vaultkeeper/cli-test-helpers'

/** Assert a NotCapableError refusal that names qualifying backends. */
function expectNotCapable(stderr: string): void {
  expect(stderr).toContain('NotCapableError')
  expect(stderr).toContain("active backend ('file')")
  expect(stderr).toContain('YubiKey')
  expect(stderr).toContain('1Password')
}

describe('--require-presence-per-use against a non-qualifying backend', () => {
  let env: CliTestEnv | undefined

  afterEach(async () => {
    if (env !== undefined) {
      await env.cleanup()
      env = undefined
    }
  })

  it('store refuses with NotCapableError (exit 1)', async () => {
    env = await createCliTestEnv()
    const result = await env.runWithStdin(
      ['store', '--name', 'api-key', '--require-presence-per-use', '--skip-doctor'],
      'sk-live-abc123',
    )
    expect(result.exitCode).toBe(1)
    expectNotCapable(result.stderr)
  })

  it('delete refuses with NotCapableError (exit 1)', async () => {
    env = await createCliTestEnv()
    // Store a secret first (without the flag), so the refusal is the presence
    // gate — not a missing secret.
    const stored = await env.runWithStdin(['store', '--name', 'api-key', '--skip-doctor'], 'v')
    expect(stored.exitCode).toBe(0)

    const result = await env.run([
      'delete',
      '--name',
      'api-key',
      '--require-presence-per-use',
      '--skip-doctor',
    ])
    expect(result.exitCode).toBe(1)
    expectNotCapable(result.stderr)
    // The secret must still exist — the delete was refused before any touch.
    const deleted = await env.run(['delete', '--name', 'api-key', '--skip-doctor'])
    expect(deleted.exitCode).toBe(0)
  })

  it('sign refuses with NotCapableError (exit 1)', async () => {
    env = await createCliTestEnv()
    const created = await env.run([
      'key',
      'create',
      '--name',
      'approval',
      '--type',
      'ed25519',
      '--skip-doctor',
    ])
    expect(created.exitCode).toBe(0)

    const result = await env.runWithStdin(
      ['sign', '--name', 'approval', '--require-presence-per-use', '--skip-doctor'],
      'gate:token:123',
    )
    expect(result.exitCode).toBe(1)
    expectNotCapable(result.stderr)
  })

  it('exec refuses with NotCapableError (exit 1) before spawning the command', async () => {
    env = await createCliTestEnv()
    const stored = await env.runWithStdin(
      ['store', '--name', 'db-pass', '--skip-doctor'],
      'hunter2',
    )
    expect(stored.exitCode).toBe(0)

    const result = await env.run([
      'exec',
      '--secret',
      'db-pass',
      '--env',
      'DB_PASS',
      '--caller',
      process.execPath,
      '--yes',
      '--require-presence-per-use',
      '--skip-doctor',
      '--',
      'node',
      '-e',
      'process.stdout.write(process.env.DB_PASS ?? "")',
    ])
    expect(result.exitCode).toBe(1)
    expectNotCapable(result.stderr)
    // The wrapped command never ran, so the secret never reached its output.
    expect(result.stdout).not.toContain('hunter2')
  })
})
