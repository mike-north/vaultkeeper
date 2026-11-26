/**
 * UATs for issue #181: `store`, `config show`, `delete`, and `exec` against a
 * config DIRECTORY the process cannot read (chmod-000) previously aborted with
 * a raw Node `Error: EACCES: permission denied, access '.../config.json'`
 * (leaked from the shared `configFileExists` presence pre-check) — no error
 * class, no fix hint. Wave-6 (#169) fixed only `doctor`.
 *
 * Each of the four commands must instead render the read failure through the
 * SAME typed `FilesystemError` construction + CLI rendering `doctor` uses:
 * a human message naming the file and pointing at permissions, a non-zero
 * exit, and NO raw `EACCES` / `access '...'` errno string.
 */
import { describe, it, expect, afterEach } from 'vitest'
import * as fs from 'node:fs/promises'
import { createCliTestEnv } from '@vaultkeeper/cli-test-helpers'
import type { CliResult, CliTestEnv } from '@vaultkeeper/cli-test-helpers'

// A chmod-000 directory only yields EACCES on POSIX, and not for root (which
// bypasses permission bits), so this repro is guarded to a non-root POSIX host
// (matches the doctor #169 guard).
const canTestDirPermissions =
  process.platform !== 'win32' && !(typeof process.getuid === 'function' && process.getuid() === 0)

/** Assert the shared "unreadable config" contract on a command's result. */
function expectUnreadableConfigContract(result: CliResult, configPath: string): void {
  // Non-zero exit — an unreadable config is a real failure, never a success.
  expect(result.exitCode).not.toBe(0)

  // The raw Node errno string never leaks to the user (neither stream).
  expect(result.stdout).not.toContain('EACCES')
  expect(result.stderr).not.toContain('EACCES')
  expect(result.stderr).not.toMatch(/access '.*config\.json'/)

  // A typed, human FilesystemError naming the file and pointing at permissions
  // — the exact wording doctor produces (issue #169).
  expect(result.stderr).toContain('FilesystemError')
  expect(result.stderr).toContain(configPath)
  expect(result.stderr).toContain('could not be read')
  expect(result.stderr).toContain('permissions')
}

describe.skipIf(!canTestDirPermissions)(
  'unreadable config dir renders a typed FilesystemError, not a raw EACCES (issue #181)',
  () => {
    let env: CliTestEnv | undefined
    let lockedDir: string | undefined

    afterEach(async () => {
      // Restore traversal so the harness can remove the temp tree, even if an
      // assertion threw before the in-test restore ran.
      if (lockedDir !== undefined) {
        await fs.chmod(lockedDir, 0o755).catch(() => undefined)
        lockedDir = undefined
      }
      if (env !== undefined) {
        await env.cleanup()
        env = undefined
      }
    })

    /**
     * Lock the config dir (chmod 000) so reading config.json inside it fails
     * with EACCES, run `args`, then restore traversal immediately so later
     * assertions can't leave a locked tree.
     */
    async function runAgainstLockedConfig(args: string[], stdin?: string): Promise<CliResult> {
      // 'flag' mode so `--config-dir` names the dir explicitly and no
      // VAULTKEEPER_CONFIG_DIR is inherited.
      env = await createCliTestEnv({ configDirMode: 'flag' })
      lockedDir = env.configDir
      await fs.chmod(env.configDir, 0o000)
      // The global --config-dir flag must precede the subcommand (and, for
      // `exec`, its `--` separator) — anything after `exec`'s `--` is the
      // wrapped command, not a global flag.
      const withDir = ['--config-dir', env.configDir, ...args]
      const result =
        stdin !== undefined ? await env.runWithStdin(withDir, stdin) : await env.run(withDir)
      await fs.chmod(env.configDir, 0o755)
      lockedDir = undefined
      return result
    }

    it('store', async () => {
      const result = await runAgainstLockedConfig(['store', '--name', 'FOO'], 'secret-value')
      expectUnreadableConfigContract(result, `${env?.configDir ?? ''}/config.json`)
    })

    it('config show', async () => {
      const result = await runAgainstLockedConfig(['config', 'show'])
      expectUnreadableConfigContract(result, `${env?.configDir ?? ''}/config.json`)
    })

    it('delete', async () => {
      const result = await runAgainstLockedConfig(['delete', '--name', 'FOO'])
      expectUnreadableConfigContract(result, `${env?.configDir ?? ''}/config.json`)
    })

    it('exec', async () => {
      const result = await runAgainstLockedConfig([
        'exec',
        '--secret',
        'FOO',
        '--env',
        'FOO',
        '--caller',
        '/bin/echo',
        '--',
        '/bin/echo',
        'hi',
      ])
      expectUnreadableConfigContract(result, `${env?.configDir ?? ''}/config.json`)
    })
  },
)
