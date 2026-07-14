/**
 * Global `--config-dir` flag extraction and resolution.
 *
 * Precedence: `--config-dir <path>` flag, then `VAULTKEEPER_CONFIG_DIR`
 * (resolved by the library's `getDefaultConfigDir`), then the
 * platform-appropriate default.
 *
 * @internal
 */

import { getDefaultConfigDir } from 'vaultkeeper'

/** Thrown when `--config-dir` is given without a following value. */
export class ConfigDirFlagError extends Error {}

/** Result of extracting the global `--config-dir` flag from an argv array. */
export interface ExtractedConfigDir {
  /** The flag's value, or `undefined` if `--config-dir` was not present. */
  configDir: string | undefined
  /** `argv` with the `--config-dir` flag (and its value) removed. */
  rest: string[]
}

/**
 * Extract a `--config-dir <path>` / `--config-dir=<path>` flag from `argv`.
 *
 * Scanning stops at the first bare `--` token so that a wrapped command's
 * own `--config-dir` (e.g. after `vaultkeeper exec ... -- --config-dir X`)
 * is left untouched and passed through to the child process.
 */
export function extractConfigDirFlag(argv: string[]): ExtractedConfigDir {
  const rest: string[] = []
  let configDir: string | undefined

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (arg === undefined) {
      continue
    }

    // Stop scanning at the first bare `--`: everything after it belongs to
    // the wrapped command (e.g. `exec ... -- --config-dir X`), not us.
    if (arg === '--') {
      rest.push(...argv.slice(i))
      break
    }

    if (arg === '--config-dir') {
      const value = argv[i + 1]
      if (value === undefined) {
        throw new ConfigDirFlagError('--config-dir requires a value')
      }
      configDir = value
      i++
      continue
    }

    if (arg.startsWith('--config-dir=')) {
      configDir = arg.slice('--config-dir='.length)
      continue
    }

    rest.push(arg)
  }

  return { configDir, rest }
}

/**
 * Resolve the effective config directory: the flag value if given,
 * otherwise the library's env-var-or-platform-default resolution.
 */
export function resolveConfigDir(flagValue: string | undefined): string {
  if (flagValue !== undefined && flagValue !== '') {
    return flagValue
  }
  return getDefaultConfigDir()
}

/** Help text fragment shared by every command that supports `--config-dir`. */
export const CONFIG_DIR_HELP_OPTION = '  --config-dir <path>  Override the config directory\n'

/** Help text fragment for the `VAULTKEEPER_CONFIG_DIR` env var. */
export const CONFIG_DIR_HELP_ENV = '  VAULTKEEPER_CONFIG_DIR=<path>   Override the config directory\n'
