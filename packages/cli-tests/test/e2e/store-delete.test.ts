/**
 * UATs for the store and delete secret lifecycle.
 *
 * Note: store and delete commands call VaultKeeper.init() which runs doctor
 * checks. If doctor fails (e.g., missing system dependencies), these tests
 * will show that failure rather than testing the store/delete logic. This is
 * expected — the UATs exercise the real CLI path.
 */
import { describe, it, expect, afterEach } from 'vitest'
import * as fs from 'node:fs/promises'
import * as os from 'node:os'
import * as path from 'node:path'
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
      result.stderr.includes('No secret provided on stdin') || result.stderr.includes('doctor')
    expect(matchesExpected).toBe(true)
  })

  // Regression: issue #60 — the CLI ignored BackendConfig.path and always wrote
  // to $HOME/.vaultkeeper/file. Store and delete must honor the configured path.
  it('honors a custom file backend path for store and delete', async () => {
    const customDir = await fs.mkdtemp(path.join(os.tmpdir(), 'vk-cli-custom-'))
    const fakeHome = await fs.mkdtemp(path.join(os.tmpdir(), 'vk-cli-home-'))
    try {
      env = await createCliTestEnv({
        config: {
          version: 1,
          backends: [{ type: 'file', enabled: true, path: customDir }],
          keyRotation: { gracePeriodDays: 7 },
          defaults: { ttlMinutes: 60, trustTier: 3 },
        },
        env: { HOME: fakeHome },
      })

      const stored = await env.runWithStdin(
        ['store', '--name', 'api-key', '--skip-doctor'],
        'sk-live-abc123',
      )
      expect(stored.exitCode).toBe(0)

      // Secret landed under the configured directory...
      const customEntries = await fs.readdir(customDir)
      expect(customEntries.some((f) => f.endsWith('.enc'))).toBe(true)

      // ...and NOT under the default $HOME/.vaultkeeper/file location.
      await expect(fs.readdir(path.join(fakeHome, '.vaultkeeper', 'file'))).rejects.toMatchObject({
        code: 'ENOENT',
      })

      // Delete removes the secret from the same configured directory.
      const deleted = await env.run(['delete', '--name', 'api-key', '--skip-doctor'])
      expect(deleted.exitCode).toBe(0)
      const afterDelete = await fs.readdir(customDir)
      expect(afterDelete.some((f) => f.endsWith('.enc'))).toBe(false)
    } finally {
      await fs.rm(customDir, { recursive: true, force: true })
      await fs.rm(fakeHome, { recursive: true, force: true })
    }
  })

  // Repro from issue #68: store previously failed on a corrupt config with
  // "Failed to parse config file at <path>" and no location or remediation.
  // The error must now include the file path, a parse location, and a
  // remediation hint naming `vaultkeeper config init`.
  //
  // Issue #114 (acceptance criterion 4): a user running `vaultkeeper store`
  // is already running the CLI, so the remediation must be CLI-native
  // ("run `vaultkeeper config init --force`") — never the library's
  // "install @vaultkeeper/cli" text, which is the wrong advice for someone
  // who already has it installed.
  it('store should exit non-zero with a CLI-native remediation (path, parse location, config init --force) for corrupt config.json (issues #68, #114)', async () => {
    env = await createCliTestEnv()
    await fs.writeFile(path.join(env.configDir, 'config.json'), '{ bad json', 'utf8')
    const result = await env.runWithStdin(
      ['store', '--name', 'test-secret', '--skip-doctor'],
      'sk-live-abc123',
    )
    expect(result.exitCode).not.toBe(0)
    expect(result.stderr).toContain(path.join(env.configDir, 'config.json'))
    expect(result.stderr).toMatch(/line \d+, column \d+/)
    expect(result.stderr).toContain('vaultkeeper config init --force')
    expect(result.stderr).not.toContain('install @vaultkeeper/cli')
  })

  // No-config story (issue #68): store falls back to the default backend and
  // says so, the same as config show/doctor/delete/exec. Issue #98: that
  // default is the safe file backend, and the hint spells out --backend.
  it('store should report a default-backend message naming the file backend when no config file exists', async () => {
    env = await createCliTestEnv()
    await fs.rm(path.join(env.configDir, 'config.json'))
    const result = await env.runWithStdin(
      ['store', '--name', 'test-secret', '--skip-doctor'],
      'sk-live-abc123',
    )
    expect(result.stderr).toContain('No config file found')
    expect(result.stderr).toContain('using the default backend (file)')
    expect(result.stderr).toContain('vaultkeeper config init --backend file')
  })
})
