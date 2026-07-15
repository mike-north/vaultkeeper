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

  // Regression: issue #118 — empty stdin previously exited 1 (runtime error)
  // while an empty/missing --name exits 2 (usage error) for the same
  // underlying problem (no usable secret input). Both must now agree.
  //
  // storeCommand reads and validates stdin BEFORE calling VaultKeeper.init()
  // (see packages/cli/src/commands/store.ts), so doctor never runs before
  // this check — --skip-doctor here only removes an unrelated source of
  // flakiness on systems missing an optional dependency, it does not change
  // which path is under test. The outcome is deterministic either way.
  it('store should exit 2 when stdin is empty (issue #118)', async () => {
    env = await createCliTestEnv()
    const result = await env.runWithStdin(['store', '--name', 'test-secret', '--skip-doctor'], '')
    expect(result.exitCode).toBe(2)
    expect(result.stderr).toContain('No secret provided on stdin')
  })

  // Regression: issue #118 — delete previously surfaced the file backend's
  // own not-found message ("Secret not found in file store: x") instead of
  // the consistent, hint-bearing wording exec.ts uses for the same failure.
  it('delete should exit non-zero with the consistent SecretNotFoundError wording and a recovery hint for a nonexistent secret (issue #118)', async () => {
    env = await createCliTestEnv()
    const result = await env.run(['delete', '--name', 'never-stored', '--skip-doctor'])
    expect(result.exitCode).not.toBe(0)
    expect(result.stderr).toContain('SecretNotFoundError')
    expect(result.stderr).toContain('Secret "never-stored" not found in the "file" backend')
    expect(result.stderr).toContain('Run `vaultkeeper store --name never-stored` to create it')
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
