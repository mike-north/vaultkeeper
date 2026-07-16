/**
 * Formatted output helpers for CLI display.
 *
 * @internal
 */

import * as path from 'node:path'
import {
  ConfigParseError,
  ConfigValidationError,
  FilesystemError,
  getPlatformDefaultConfigDir,
} from 'vaultkeeper'
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
 * Whether `configDir` refers to the machine's platform-default config dir,
 * compared by normalized path so a differently-spelled but equivalent form
 * (trailing slash, relative path, and — on Windows — different casing) is
 * still recognized as the default and doesn't wrongly leak a `--config-dir`
 * into the default-case hint (issue #149 review). The default is the
 * env-INDEPENDENT platform default, so a dir that came only from
 * `VAULTKEEPER_CONFIG_DIR` is still treated as non-default.
 */
function isPlatformDefaultConfigDir(configDir: string): boolean {
  const normalize = (p: string): string => {
    const resolved = path.resolve(p)
    return process.platform === 'win32' ? resolved.toLowerCase() : resolved
  }
  return normalize(configDir) === normalize(getPlatformDefaultConfigDir())
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
 * surface (issue #137). `configDir` is used both as a fallback for
 * `ConfigValidationError.configFilePath` (`undefined` when the error came
 * from validating an in-memory value rather than a loaded file — a case the
 * CLI itself never hits, since it only ever validates via
 * `loadConfig`/`VaultKeeper.init`) and to decide whether the printed recovery
 * command needs an explicit `--config-dir` (issue #149).
 */
function configRemediation(
  configPath: string,
  detail: string | undefined,
  configDir: string,
): string {
  const detailSuffix = detail !== undefined ? ` (${detail})` : ''
  // A bare `config init --force` writes to the machine's platform-default
  // config dir. When the active config dir is anything else, the pasted
  // command would create a fresh default config and leave the diagnosed file
  // corrupt (issue #149). Carry an explicit `--config-dir` so the command
  // repairs the exact file it complained about.
  return (
    `The config at \`${configPath}\` is invalid${detailSuffix} — ` +
    `run \`vaultkeeper config init --force${configInitDirFlag(configDir)}\` to overwrite it.`
  )
}

/**
 * The `--config-dir` suffix a printed `config init --force` command needs so it
 * repairs the exact file that was diagnosed rather than the machine default: an
 * empty string when `configDir` already is the platform default, otherwise a
 * shell-quoted ` --config-dir <dir>` (issue #149).
 */
function configInitDirFlag(configDir: string): string {
  return isPlatformDefaultConfigDir(configDir) ? '' : ` --config-dir ${shellQuote(configDir)}`
}

/**
 * CLI-native remediation for a `config-unknown-backend` doctor failure: name
 * the offending backend type and the valid options — the same guidance the
 * runtime `BackendUnavailableError` gives — then point at `config init --force`
 * (issue #215). The valid options come from the structured
 * `knownBackendTypes`; on the off chance they are absent, the message still
 * names the bad type and the recovery command.
 */
function configUnknownBackendRemediation(error: PreflightCheckError, configDir: string): string {
  const known = error.knownBackendTypes ?? []
  const typeLabel = error.backendType !== undefined ? ` "${error.backendType}"` : ''
  const available = known.length > 0 ? ` Available types: ${known.join(', ')}.` : ''
  return (
    `The config at \`${error.configPath}\` names an unknown backend type${typeLabel}.${available} ` +
    `Run \`vaultkeeper config init --force${configInitDirFlag(configDir)}\` to overwrite it, ` +
    `or edit the config to use a valid backend type.`
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
  return `${err.name}: ${configRemediation(configPath, detail, configDir)}`
}

/**
 * True when `err` is the `FilesystemError` `loadConfig` throws for a failed
 * read of `config.json` — any errno (`EACCES`/`EPERM`/`EISDIR`/etc.), not
 * only permission failures; `formatConfigReadError` picks the actual wording
 * from `err.code`. `FileBackend` secret reads never live at
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
 * Errno codes handled by `isUnreadableConfigFile` that are actually
 * permission problems. `undefined` (no errno code recovered — see
 * `FilesystemError.code`'s docs) is treated the same way, conservatively:
 * it's the pre-#141 shape, and a permissions hint is still broadly correct
 * for a read failure of unknown cause.
 */
const PERMISSION_ERROR_CODES = new Set(['EACCES', 'EPERM'])

/**
 * Build the CLI-native remediation for an unreadable `config.json`.
 *
 * Regression: issue #114 fixed this wrong-audience remediation for parse and
 * validation errors, but the read-failure path (`FilesystemError` from an
 * EACCES/EPERM `config.json`, e.g. a root-owned or chmod'd file) still fell
 * through to `formatError`'s generic `Error` branch, printing the library's
 * own message — which still names `install @vaultkeeper/cli` (issue #137).
 * The remediation here deliberately does NOT suggest `config init --force`
 * for any variant below: that command would either hit the exact same read
 * failure trying to write the replacement file (a permission problem) or be
 * the wrong fix entirely (e.g. overwriting a directory doesn't make it a
 * file) — a dead end either way.
 *
 * Review follow-up (issue #137, PR #158): an earlier draft suggested running
 * `ls -l <path>` as an example command. That's POSIX-only — confusing on
 * Windows, which this CLI supports via the dpapi backend — and embedded the
 * path unquoted, which breaks if it contains spaces/metacharacters (e.g. a
 * user-supplied `--config-dir`). Platform-neutral prose avoids both problems
 * without introducing platform-branching for a single message.
 *
 * Review follow-up (issue #137, PR #158): `isUnreadableConfigFile` matches
 * *any* read-path `FilesystemError` on `config.json`, not only permission
 * failures — `EISDIR`, `ENOSPC`-adjacent codes, etc. can also reach here, and
 * asserting "the current user cannot read it" would be an outright wrong
 * diagnosis for those. `FilesystemError.code` (added in #141) lets this
 * branch on the actual errno rather than assume permissions: a genuine
 * permission code (or no code at all, conservatively) keeps the permissions
 * wording; any other code gets an honest, code-naming message instead.
 */
function configReadRemediation(configPath: string, code: string | undefined): string {
  if (code === undefined || PERMISSION_ERROR_CODES.has(code)) {
    return (
      `The config at \`${configPath}\` could not be read — ` +
      "check the file's permissions and ownership, and that it exists — the " +
      'current user cannot read it. Then try again.'
    )
  }
  return (
    `The config at \`${configPath}\` could not be read (${code}) — ` +
    'check that the path is a regular, readable file, then try again.'
  )
}

function formatConfigReadError(err: FilesystemError): string {
  return `${err.name}: ${configReadRemediation(err.path, err.code)}`
}

/**
 * Build the CLI-native remediation for a doctor `config` preflight failure
 * from its structured, remediation-free {@link PreflightCheckError}. Shares
 * the exact wording of {@link formatError}'s config-error message so `doctor`
 * and every other command speak with one voice — and, like it, never repeats
 * the library's "install @vaultkeeper/cli" text to a user already running
 * the CLI.
 */
export function formatPreflightConfigError(error: PreflightCheckError, configDir: string): string {
  // A read failure (permission/EISDIR/etc.) has a different remediation from a
  // parse/validation failure: `config init --force` cannot repair a config the
  // process cannot read, so point at the file's permissions instead, sharing
  // the exact wording of `formatError`'s unreadable-`config.json` message.
  if (error.kind === 'config-read') {
    return configReadRemediation(error.configPath, error.code)
  }
  // An unknown backend type gets the same "valid types" guidance the runtime
  // BackendUnavailableError gives, so `doctor` names both the offending type
  // and the valid options instead of a bare "invalid" (issue #215).
  if (error.kind === 'config-unknown-backend') {
    return configUnknownBackendRemediation(error, configDir)
  }
  // Surface the field-level detail the same way `formatConfigError` does for a
  // non-doctor validation error: a parse failure carries a `location`
  // (`at line N, column N`); a validation failure carries the offending
  // `field` (backtick-wrapped, e.g. `` `backends` ``), so doctor and every
  // other command name the same detail with one voice (issue #202).
  const detail =
    error.location !== undefined
      ? `at ${error.location}`
      : error.field !== undefined
        ? `\`${error.field}\``
        : undefined
  return configRemediation(error.configPath, detail, configDir)
}

/**
 * Past-tense description of the filesystem operation a {@link FilesystemError}
 * was attempting, keyed by its `permission` field, for use in a human-facing
 * "cannot be <verb>" sentence.
 */
const FS_OPERATION_VERB: Record<string, string> = {
  read: 'read',
  write: 'written',
  execute: 'executed',
  delete: 'deleted',
  // `FileBackend` uses the permission set `'rwx'` (not an operation verb) when
  // it fails to create its storage directory, so map it to the operation that
  // actually failed rather than the generic "accessed" fallback.
  rwx: 'created',
}

/**
 * Classify a {@link FilesystemError} as `'missing'` (ENOENT), `'denied'`
 * (EACCES/EPERM), or `'other'`, to pick the human-facing wording.
 *
 * Prefers the typed, machine-readable `err.code` — its documented contract
 * (see `FilesystemError.code`) says to prefer it over parsing the message,
 * which is not a contractual format and could misclassify if a path happens
 * to contain one of these tokens. Falls back to a conservative message-regex
 * only when `code` is `undefined` (a legacy or hand-constructed error with no
 * underlying cause, e.g. some unit fixtures).
 */
function classifyFilesystemError(err: FilesystemError): 'missing' | 'denied' | 'other' {
  const code = err.code
  if (code !== undefined) {
    if (code === 'ENOENT') {
      return 'missing'
    }
    if (code === 'EACCES' || code === 'EPERM') {
      return 'denied'
    }
    return 'other'
  }
  // No typed code — fall back to the (non-contractual) message text.
  if (/\bENOENT\b/.test(err.message)) {
    return 'missing'
  }
  if (/\b(?:EACCES|EPERM)\b/.test(err.message)) {
    return 'denied'
  }
  return 'other'
}

/**
 * Build a human-facing message for a {@link FilesystemError} from its typed
 * `path`/`permission`/`code` fields, without ever echoing the raw Node
 * `ENOENT: … open '<path>'` text — which leaks an implementation detail and
 * carries no next step (issue #150). Mirrors the fix-oriented shape of the
 * config-error and identity-mismatch messages.
 */
function formatFilesystemError(err: FilesystemError): string {
  const quotedPath = `\`${err.path}\``
  const kind = classifyFilesystemError(err)
  if (kind === 'missing') {
    return (
      `${err.name}: The file at ${quotedPath} does not exist. ` +
      'Check that the path is correct and the file exists, then try again.'
    )
  }
  const verb = FS_OPERATION_VERB[err.permission] ?? 'accessed'
  if (kind === 'denied') {
    return (
      `${err.name}: The file at ${quotedPath} cannot be ${verb} (permission denied). ` +
      "Check the file's permissions and try again."
    )
  }
  // Any other filesystem failure: still avoid leaking the raw OS text, but
  // keep the operation context carried by the typed `permission` field.
  return (
    `${err.name}: The file at ${quotedPath} could not be ${verb}. ` +
    "Check the path and the file's permissions, then try again."
  )
}

/**
 * Which command is looking the secret up, so {@link secretNotFoundMessage} can
 * pick a recovery hint that fits the caller's intent:
 *
 * - `'access'` — a command that needs the secret to exist (`exec`, and any
 *   future read path). Suggesting `store` to create it is the right next step.
 * - `'delete'` — the user is trying to *remove* the secret. Telling them to
 *   run `store` to *create* the very thing they are deleting is nonsensical
 *   (issue #183), so the delete hint is neutral and suggests no creation.
 */
export type SecretLookupContext = 'access' | 'delete'

/**
 * Build the standard "secret not found" message, shared by every CLI command
 * that looks up a secret before acting on it.
 *
 * Regression: issue #118 — `exec` and `delete` previously reported different
 * wording for the identical failure (`exec` said `Secret "x" not found in
 * file backend`; `delete` surfaced the backend's own `Secret not found in
 * file store: x`), and neither pointed the user at a fix. Centralizing the
 * wording here, and having each command construct the error from this helper
 * instead of the backend's own message, guarantees they stay in sync.
 *
 * The recovery hint is chosen by `context` (issue #183): the shared diagnostic
 * sentence is identical, but `delete` must not be told to `store` (create) the
 * secret it is trying to remove — the old shared wording did exactly that.
 */
export function secretNotFoundMessage(
  name: string,
  backendType: string,
  context: SecretLookupContext = 'access',
): string {
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
  const diagnostic = `Secret ${JSON.stringify(name)} not found in the ${JSON.stringify(backendType)} backend.`

  if (context === 'delete') {
    // No `store` suggestion: the user is deleting, not creating. The neutral
    // hint names the two ordinary explanations for a delete missing its
    // target so the message is still actionable without being contradictory.
    return `${diagnostic} It may have already been deleted, or the name may be misspelled.`
  }

  // The access-path recovery hint is a literal shell command a user may copy
  // and paste, so `name` is wrapped with shellQuote() (single-quote POSIX
  // shell escaping) — JSON's escaping isn't shell-safe and an unescaped name
  // could contain a quote, breaking the pasted command (review follow-up,
  // issue #118).
  return `${diagnostic} Run \`vaultkeeper store --name ${shellQuote(name)}\` to create it.`
}

/** Format an error for display on stderr. */
export function formatError(err: unknown, configDir: string): string {
  if (err instanceof ConfigParseError || err instanceof ConfigValidationError) {
    return formatConfigError(err, configDir)
  }
  // The specific unreadable-`config.json` case gets config-oriented wording
  // (issue #137); every other FilesystemError (e.g. an unreadable executable
  // on the `approve` path) gets the general polished message (issue #150).
  if (isUnreadableConfigFile(err, configDir)) {
    return formatConfigReadError(err)
  }
  if (err instanceof FilesystemError) {
    return formatFilesystemError(err)
  }
  if (err instanceof Error) {
    return `${err.name}: ${err.message}`
  }
  return String(err)
}
