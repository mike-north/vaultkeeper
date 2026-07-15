/**
 * Formatted output helpers for CLI display.
 *
 * @internal
 */

import * as path from 'node:path'
import { ConfigParseError, ConfigValidationError, FilesystemError } from 'vaultkeeper'
import type { PreflightCheckError } from 'vaultkeeper'
import { shellQuote } from './shell-quote.js'

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
 * (the file path, and — for a parse error, its line/column location; for a
 * validation error, its `field`); the library-internal validation *reason*
 * text (e.g. "must be a non-empty string") lives only in `.message`
 * alongside the wrong remediation, so it is deliberately not reused here —
 * but `field` (the dotted/bracketed path to the offending field, e.g.
 * `version`) is itself a structured, remediation-free field and safe to
 * surface (issue #137). `configDir` is a fallback for
 * `ConfigValidationError.configFilePath`, which is `undefined` when the
 * error came from validating an in-memory value rather than a loaded file —
 * a case the CLI itself never hits, since it only ever validates via
 * `loadConfig`/`VaultKeeper.init`.
 */
function configRemediation(configPath: string, detail: string | undefined): string {
  const detailSuffix = detail !== undefined ? ` (${detail})` : ''
  return (
    `The config at \`${configPath}\` is invalid${detailSuffix} — ` +
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
  const detail =
    err instanceof ConfigParseError
      ? err.location !== undefined
        ? `at ${err.location}`
        : undefined
      : `\`${err.field}\``
  return `${err.name}: ${configRemediation(configPath, detail)}`
}

/**
 * True when `err` is the `FilesystemError` `loadConfig` throws for an
 * unreadable `config.json` (e.g. `EACCES`/`EPERM`) — as opposed to any other
 * filesystem failure. `FileBackend` secret reads never live at
 * `configDir/config.json`, so this check can't collide with a backend read
 * failure (issue #137).
 */
function isUnreadableConfigFile(err: unknown, configDir: string): err is FilesystemError {
  return (
    err instanceof FilesystemError &&
    err.permission === 'read' &&
    err.path === path.join(configDir, 'config.json')
  )
}

/**
 * Build the CLI-native remediation for an unreadable `config.json`.
 *
 * Regression: issue #114 fixed this wrong-audience remediation for parse and
 * validation errors, but the read-failure path (`FilesystemError` from an
 * EACCES/EPERM `config.json`, e.g. a root-owned or chmod'd file) still fell
 * through to `formatError`'s generic `Error` branch, printing the library's
 * own message — which still names `install @vaultkeeper/cli` (issue #137).
 * The remediation here deliberately does NOT suggest `config init --force`:
 * that command would hit the exact same permission error trying to write the
 * replacement file, so it's a dead end for this failure mode.
 */
function formatConfigReadError(err: FilesystemError): string {
  return (
    `${err.name}: The config at \`${err.path}\` could not be read — ` +
    'check that the file exists and that your user has permission to read it ' +
    `(e.g. \`ls -l ${err.path}\`), then try again.`
  )
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
  const detail = error.location !== undefined ? `at ${error.location}` : undefined
  return configRemediation(error.configPath, detail)
}

/**
 * Build the standard "secret not found" message, shared by every CLI command
 * that looks up a secret before acting on it.
 *
 * Regression: issue #118 — `exec` and `delete` previously reported different
 * wording for the identical failure (`exec` said `Secret "x" not found in
 * file backend`; `delete` surfaced the backend's own `Secret not found in
 * file store: x`), and neither pointed the user at a fix. Centralizing the
 * wording here, and having each command construct the error from this helper
 * instead of the backend's own message, guarantees they stay in sync and
 * always include a recovery hint.
 */
export function secretNotFoundMessage(name: string, backendType: string): string {
  // The diagnostic sentence and the recovery hint each need their own kind
  // of quoting, since they aren't the same kind of text:
  //
  // - The diagnostic ("Secret "x" not found...") is English prose — the
  //   quotes are just readability punctuation around the name. JSON.stringify
  //   escapes an embedded `"` so it can't unbalance those quotes.
  //   `backendType` can only ever be one of the fixed registry identifiers
  //   (file/keychain/dpapi/secret-tool/1password/yubikey — see
  //   packages/vaultkeeper/src/backend/register-builtins.ts), none of which
  //   contain a quote, but `name` is user-supplied and, on the exec path
  //   (`--secret`), is validated only for non-emptiness — not restricted to
  //   store/delete's safe `--name` character set — so it needs the escaping.
  // - The recovery hint is a literal shell command a user may copy and
  //   paste, so `name` is wrapped with shellQuote() (single-quote POSIX
  //   shell escaping) instead — JSON's escaping isn't shell-safe and an
  //   unescaped name could contain a quote, breaking the pasted command
  //   (review follow-up, issue #118).
  return (
    `Secret ${JSON.stringify(name)} not found in the ${JSON.stringify(backendType)} backend. ` +
    `Run \`vaultkeeper store --name ${shellQuote(name)}\` to create it.`
  )
}

/** Format an error for display on stderr. */
export function formatError(err: unknown, configDir: string): string {
  if (err instanceof ConfigParseError || err instanceof ConfigValidationError) {
    return formatConfigError(err, configDir)
  }
  if (isUnreadableConfigFile(err, configDir)) {
    return formatConfigReadError(err)
  }
  if (err instanceof Error) {
    return `${err.name}: ${err.message}`
  }
  return String(err)
}
