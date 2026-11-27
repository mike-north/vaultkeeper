/**
 * UATs for the store and delete secret lifecycle.
 *
 * Note: store and delete commands call VaultKeeper.init() which runs doctor
 * checks. If doctor fails (e.g., missing system dependencies), these tests
 * will show that failure rather than testing the store/delete logic. This is
 * expected — the UATs exercise the real CLI path.
 */
import { describe, it, expect, afterEach, vi } from 'vitest'
import * as fs from 'node:fs/promises'
import * as os from 'node:os'
import * as path from 'node:path'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { createCliTestEnv } from '@vaultkeeper/cli-test-helpers'
import { VaultKeeper } from 'vaultkeeper'
import { FileBackend } from '../../../vaultkeeper/src/backend/file-backend.js'
import type { CliTestEnv } from '@vaultkeeper/cli-test-helpers'

describe('store and delete lifecycle', () => {
  let env: CliTestEnv | undefined

  afterEach(async () => {
    if (env !== undefined) {
      await env.cleanup()
      env = undefined
    }
  })

  it('preserves trailing characters and supports raw line endings', async () => {
    env = await createCliTestEnv()
    const backend = new FileBackend(undefined, env.configDir)
    const cases: [string, boolean, string][] = [
      ['value \t', false, 'value \t'],
      ['value \t\r\n', false, 'value \t'],
      ['value\n\n', false, 'value\n'],
      ['value \t\r\n', true, 'value \t\r\n'],
      ['\uFEFFvalue\r', true, '\uFEFFvalue\r'],
    ]
    for (const [input, raw, expected] of cases) {
      const args = ['store', '--name', 'trailing', '--skip-doctor']
      if (raw) args.push('--raw')
      expect((await env.runWithStdin(args, input)).exitCode).toBe(0)
      expect(await backend.retrieve('trailing')).toBe(expected)
    }
  })

  it('rejects whitespace-only input in either mode without overwriting a usable secret', async () => {
    env = await createCliTestEnv()
    const args = ['store', '--name', 'trailing', '--skip-doctor']
    expect((await env.runWithStdin(args, 'original')).exitCode).toBe(0)

    // Token authorization requires a value with at least one non-whitespace character.
    for (const { flags, input } of [
      { flags: [], input: ' \t\n' },
      { flags: ['--raw'], input: ' \t\u00A0\n' },
    ]) {
      const result = await env.runWithStdin([...args, ...flags], input)
      expect(result.exitCode).toBe(2)
      expect(result.stdout).toBe('')
      expect(result.stderr).toContain('No secret provided on stdin')
    }

    const vault = await VaultKeeper.init({ configDir: env.configDir, skipDoctor: true })
    const jwe = await vault.setup('trailing', { skipTrust: true })
    const { token } = await vault.authorize(jwe)
    vault.getSecret(token).read((value) => {
      expect(value.toString('utf8')).toBe('original')
    })
  })

  it.skipIf(process.platform === 'win32').each([
    { mode: 'raw', input: 'value \t\r\n', flags: ['--raw'], expected: 'value \t\r\n' },
    { mode: 'default', input: 'value\n\n', flags: [], expected: 'value\n' },
  ])(
    'round-trips $mode CLI store input through piped Secret Service lookup and authorization',
    async ({ input, flags, expected }) => {
      env = await createCliTestEnv({
        config: {
          version: 1,
          backends: [{ type: 'secret-tool', enabled: true }],
          keyRotation: { gracePeriodDays: 7 },
          defaults: { ttlMinutes: 60, trustTier: 3 },
        },
      })
      // Model the real tool's pipe contract: store consumes stdin and lookup
      // adds a presentation newline only when its stdout is a terminal.
      await fs.writeFile(
        path.join(env.configDir, 'secret-tool'),
        `#!/bin/sh
case "$1" in
  store) umask 077; cat > "$VK_TEST_SECRET_FILE" ;;
  lookup)
    cat "$VK_TEST_SECRET_FILE" || exit 1
    if [ -t 1 ]; then printf '\\n'; fi
    ;;
  *) exit 1 ;;
esac
`,
        { mode: 0o700 },
      )
      const secretFile = path.join(env.configDir, 'stored-secret')
      const testEnv = {
        ...process.env,
        PATH: `${env.configDir}${path.delimiter}${process.env.PATH ?? ''}`,
        VAULTKEEPER_CONFIG_DIR: env.configDir,
        VK_TEST_SECRET_FILE: secretFile,
      }
      const bin = fileURLToPath(new URL('../../../cli/dist/bin.js', import.meta.url))
      vi.stubEnv('PATH', testEnv.PATH)
      vi.stubEnv('VK_TEST_SECRET_FILE', secretFile)
      try {
        const args = ['store', '--name', 'trailing', '--skip-doctor', ...flags]
        const result = spawnSync(process.execPath, [bin, ...args], { env: testEnv, input })
        expect(result.status, result.stderr.toString()).toBe(0)
        expect(await fs.readFile(secretFile, 'utf8')).toBe(expected)

        const vault = await VaultKeeper.init({ configDir: env.configDir, skipDoctor: true })
        const jwe = await vault.setup('trailing', { skipTrust: true })
        const { token } = await vault.authorize(jwe)
        vault.getSecret(token).read((value) => {
          expect(value.toString('utf8')).toBe(expected)
        })
      } finally {
        vi.unstubAllEnvs()
      }
    },
  )

  it('rejects malformed UTF-8 without storing a modified value', async () => {
    env = await createCliTestEnv()
    const result = spawnSync(
      process.execPath,
      [
        fileURLToPath(new URL('../../../cli/dist/bin.js', import.meta.url)),
        'store',
        '--name',
        'invalid',
        '--raw',
        '--skip-doctor',
      ],
      {
        env: { ...process.env, VAULTKEEPER_CONFIG_DIR: env.configDir },
        input: Buffer.from([0xff]),
      },
    )
    expect(result.status).toBe(1)
    expect(result.stderr.toString()).toMatch(/encoded data|utf-8/i)
    await expect(new FileBackend(undefined, env.configDir).retrieve('invalid')).rejects.toThrow()
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
  // the consistent, typed SecretNotFoundError wording exec.ts uses for the
  // same failure.
  //
  // Regression: issue #183 — the shared not-found hint told the user to run
  // `store` to CREATE the secret, which is nonsensical on the delete path
  // (they are trying to REMOVE it). The delete-context message must share the
  // diagnostic sentence but never suggest creating the secret being deleted.
  it('delete should exit non-zero with the consistent SecretNotFoundError wording and a delete-appropriate hint for a nonexistent secret (issues #118, #183)', async () => {
    env = await createCliTestEnv()
    const result = await env.run(['delete', '--name', 'never-stored', '--skip-doctor'])
    expect(result.exitCode).not.toBe(0)
    expect(result.stderr).toContain('SecretNotFoundError')
    expect(result.stderr).toContain('Secret "never-stored" not found in the "file" backend')
    // The delete path must NOT tell the user to `store` (create) the secret.
    expect(result.stderr).not.toContain('to create it')
    expect(result.stderr).not.toContain('vaultkeeper store --name')
    // It gives a neutral, delete-appropriate explanation instead.
    expect(result.stderr).toContain('may have already been deleted, or the name may be misspelled')
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
