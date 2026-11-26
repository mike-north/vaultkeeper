/**
 * UATs for issue #228: `config init` and the first `store` against a config
 * directory whose PARENT is read-only previously leaked a raw, unwrapped Node
 * error — `Error: EACCES: permission denied, mkdir '<path>'` — instead of the
 * typed FilesystemError the read paths (#181/#169) already render.
 *
 * The config-dir CREATION path was the gap: `config init` (`fs.mkdir`) and the
 * key-state persistence during a first `store` (`saveKeyState`'s `fs.mkdir`)
 * were not wrapped. Both must now render a typed `FilesystemError` through the
 * CLI's `formatError`: directory-specific wording naming the path, a
 * parent-directory fix hint, a non-zero exit, and NO raw `EACCES` / `mkdir`
 * errno string.
 */
import { describe, it, expect, afterEach } from 'vitest'
import * as fs from 'node:fs/promises'
import * as path from 'node:path'
import { createCliTestEnv } from '@vaultkeeper/cli-test-helpers'
import type { CliResult, CliTestEnv } from '@vaultkeeper/cli-test-helpers'

// A chmod-500 (read-only) parent directory only denies `mkdir` on POSIX, and
// not for root (which bypasses permission bits), so this repro is guarded to a
// non-root POSIX host (matches the #181/#169 guards).
const canTestDirPermissions =
  process.platform !== 'win32' && !(typeof process.getuid === 'function' && process.getuid() === 0)

/**
 * Assert the config-dir-creation failure contract: the raw errno text never
 * leaks, and the user sees the typed, directory-oriented FilesystemError.
 */
function expectUnwritableParentContract(result: CliResult, targetDir: string): void {
  // Non-zero exit — an unwritable parent is a real failure, never a success.
  expect(result.exitCode).not.toBe(0)

  // The raw Node errno string never leaks to the user (neither stream).
  expect(result.stdout).not.toContain('EACCES')
  expect(result.stderr).not.toContain('EACCES')
  expect(result.stderr).not.toMatch(/mkdir '.*'/)

  // A typed, human FilesystemError naming the directory and pointing at the
  // parent directory as the fix.
  expect(result.stderr).toContain('FilesystemError')
  expect(result.stderr).toContain(targetDir)
  expect(result.stderr).toContain('could not be created')
  expect(result.stderr).toContain('parent directory')
}

describe.skipIf(!canTestDirPermissions)(
  'read-only parent dir renders a typed FilesystemError, not a raw EACCES mkdir (issue #228)',
  () => {
    let env: CliTestEnv | undefined
    let readonlyParent: string | undefined

    afterEach(async () => {
      // Restore write permission so the harness can remove the temp tree, even
      // if an assertion threw before any in-test restore ran.
      if (readonlyParent !== undefined) {
        await fs.chmod(readonlyParent, 0o755).catch(() => undefined)
        readonlyParent = undefined
      }
      if (env !== undefined) {
        await env.cleanup()
        env = undefined
      }
    })

    /**
     * Create a read-only parent directory inside the isolated temp env, target
     * a not-yet-existing subdirectory under it via `--config-dir`, run `args`,
     * then restore write permission immediately so later assertions can't leave
     * a locked tree. Returns the result and the (never-created) target dir.
     */
    async function runAgainstReadonlyParent(
      args: string[],
      stdin?: string,
    ): Promise<{ result: CliResult; targetDir: string }> {
      // 'flag' mode so `--config-dir` names the dir explicitly and no
      // VAULTKEEPER_CONFIG_DIR is inherited.
      env = await createCliTestEnv({ configDirMode: 'flag' })
      const parent = path.join(env.configDir, 'ro')
      await fs.mkdir(parent, { recursive: true })
      await fs.chmod(parent, 0o500)
      readonlyParent = parent
      const targetDir = path.join(parent, 'sub')

      const withDir = ['--config-dir', targetDir, ...args]
      const result =
        stdin !== undefined ? await env.runWithStdin(withDir, stdin) : await env.run(withDir)

      await fs.chmod(parent, 0o755)
      readonlyParent = undefined
      return { result, targetDir }
    }

    it('config init', async () => {
      const { result, targetDir } = await runAgainstReadonlyParent([
        'config',
        'init',
        '--backend',
        'file',
      ])
      expectUnwritableParentContract(result, targetDir)
    })

    it('store (creates the config dir on first write)', async () => {
      const { result, targetDir } = await runAgainstReadonlyParent(
        ['store', '--name', 'FOO'],
        'secret-value',
      )
      expectUnwritableParentContract(result, targetDir)
    })
  },
)
