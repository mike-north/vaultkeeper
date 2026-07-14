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

/** Return `true` if `config.json` exists under `configDir`. */
export async function configFileExists(configDir: string): Promise<boolean> {
  try {
    await fs.access(path.join(configDir, 'config.json'))
    return true
  } catch {
    return false
  }
}

/**
 * One-line advisory printed when a command falls back to platform defaults
 * because no config file exists. Always names the active backend and points
 * at `vaultkeeper config init` so the user can persist a real config.
 */
export function noConfigMessage(activeBackendType: string): string {
  return (
    `No config file found; using platform defaults (${activeBackendType}). ` +
    "Run 'vaultkeeper config init' to persist one.\n"
  )
}
