/**
 * Shared "is there a config file, and if not, what do we tell the user"
 * helpers, used uniformly across store/delete/exec/config show/doctor so all
 * five commands agree on the no-config story (issue #68): fall back to
 * platform defaults and say so, rather than silently defaulting (the old
 * store/delete/exec behavior) or erroring (the old `config show` behavior).
 *
 * @internal
 */

import * as fs from 'node:fs/promises'
import * as path from 'node:path'

/** `true` if `fs.access` failed because the config file truly does not exist. */
function isEnoent(err: unknown): boolean {
  return err instanceof Error && 'code' in err && err.code === 'ENOENT'
}

/**
 * Return `true` if `config.json` exists under `configDir` and is at least
 * readable-checkable, `false` if it is genuinely absent (`ENOENT`).
 *
 * Any other `fs.access` failure (e.g. `EACCES` on a parent directory, or a
 * permissions error on the file itself) is a real problem, not "no config" —
 * treating it as "no config" would silently fall back to platform defaults
 * for a config that actually exists but is broken, the same class of bug
 * `loadConfig`'s ENOENT-only fallback fixes (issue #68). Such errors rethrow
 * so the caller's own `loadConfig()` call surfaces the typed error instead.
 */
export async function configFileExists(configDir: string): Promise<boolean> {
  try {
    await fs.access(path.join(configDir, 'config.json'))
    return true
  } catch (err) {
    if (isEnoent(err)) {
      return false
    }
    throw err
  }
}

/**
 * One-line advisory printed when a command falls back to the default backend
 * because no config file exists. Names the active backend and points at
 * `vaultkeeper config init --backend <type>` — spelling out `--backend`
 * explicitly, never a bare `config init`, so following the hint verbatim can
 * never silently persist a different (e.g. OS-native) backend than the one the
 * fallback just reported (issue #98).
 */
export function noConfigMessage(activeBackendType: string): string {
  return (
    `No config file found; using the default backend (${activeBackendType}). ` +
    `Run 'vaultkeeper config init --backend ${activeBackendType}' to persist it.\n`
  )
}
