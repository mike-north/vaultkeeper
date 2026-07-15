/**
 * Formatted output helpers for CLI display.
 *
 * @internal
 */

import * as path from 'node:path'
import { ConfigParseError, ConfigValidationError } from 'vaultkeeper'
import type { PreflightCheckError } from 'vaultkeeper'

/** Check if stdout is a TTY at call time (not module load time). */
function isTTY(): boolean {
  return process.stdout.isTTY
}

/** Wrap text in ANSI bold if stdout is a TTY. */
export function bold(text: string): string {
  return isTTY() ? `\x1b[1m${text}\x1b[22m` : text
}

/** Wrap text in ANSI dim if stdout is a TTY. */
export function dim(text: string): string {
  return isTTY() ? `\x1b[2m${text}\x1b[22m` : text
}

/**
 * Build a CLI-native remediation message for a config parse/validation
 * error, from the errors' structured fields rather than their `.message`.
 *
 * The library's own message points a reader at installing `@vaultkeeper/cli`
 * — correct advice for a library consumer that doesn't have a CLI installed
 * (issue #100), but wrong for a user who is already running this CLI
 * (issue #114). Only structured fields that are safe to depend on are used
 * (the file path, and — for a parse error — its line/column location); the
 * library-internal validation reason text lives only in `.message`
 * alongside the wrong remediation, so it is deliberately not reused here.
 * `configDir` is a fallback for `ConfigValidationError.configFilePath`,
 * which is `undefined` when the error came from validating an in-memory
 * value rather than a loaded file — a case the CLI itself never hits, since
 * it only ever validates via `loadConfig`/`VaultKeeper.init`.
 */
function configRemediation(configPath: string, location: string | undefined): string {
  const locationSuffix = location !== undefined ? ` (at ${location})` : ''
  return (
    `The config at \`${configPath}\` is invalid${locationSuffix} — ` +
    'run `vaultkeeper config init --force` to overwrite it.'
  )
}

function formatConfigError(
  err: ConfigParseError | ConfigValidationError,
  configDir: string,
): string {
  const configPath =
    err instanceof ConfigParseError
      ? err.path
      : (err.configFilePath ?? path.join(configDir, 'config.json'))
  const location = err instanceof ConfigParseError ? err.location : undefined
  return `${err.name}: ${configRemediation(configPath, location)}`
}

/**
 * Build the CLI-native remediation for a doctor `config` preflight failure
 * from its structured, remediation-free {@link PreflightCheckError}. Shares
 * the exact wording of {@link formatError}'s config-error message so `doctor`
 * and every other command speak with one voice — and, like it, never repeats
 * the library's "install @vaultkeeper/cli" text to a user already running
 * the CLI.
 */
export function formatPreflightConfigError(error: PreflightCheckError): string {
  return configRemediation(error.configPath, error.location)
}

/** Format an error for display on stderr. */
export function formatError(err: unknown, configDir: string): string {
  if (err instanceof ConfigParseError || err instanceof ConfigValidationError) {
    return formatConfigError(err, configDir)
  }
  if (err instanceof Error) {
    return `${err.name}: ${err.message}`
  }
  return String(err)
}
