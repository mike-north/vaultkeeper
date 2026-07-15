import { describe, it, expect } from 'vitest'
import * as path from 'node:path'
import {
  ConfigParseError,
  ConfigValidationError,
  FilesystemError,
  SecretNotFoundError,
} from 'vaultkeeper'
import { formatError, formatPreflightConfigError, secretNotFoundMessage } from '../../src/output.js'
import type { PreflightCheckError } from 'vaultkeeper'

const CONFIG_DIR = '/home/user/.config/vaultkeeper'

describe('formatError', () => {
  it('should format Error instances with name and message', () => {
    const err = new Error('something broke')
    expect(formatError(err, CONFIG_DIR)).toBe('Error: something broke')
  })

  it('should format custom error classes', () => {
    class CustomError extends Error {
      constructor(message: string) {
        super(message)
        this.name = 'CustomError'
      }
    }
    expect(formatError(new CustomError('bad'), CONFIG_DIR)).toBe('CustomError: bad')
  })

  it('should stringify non-Error values', () => {
    expect(formatError('string error', CONFIG_DIR)).toBe('string error')
    expect(formatError(42, CONFIG_DIR)).toBe('42')
    expect(formatError(null, CONFIG_DIR)).toBe('null')
  })

  // Regression: issue #114 — the CLI must never surface the library's
  // "install @vaultkeeper/cli" remediation (issue #100) to a user who is
  // already running this CLI. ConfigParseError/ConfigValidationError get a
  // CLI-native message built from their structured fields instead.
  describe('config errors get a CLI-native remediation (issue #114)', () => {
    it('rewrites ConfigParseError to a CLI-native message naming the path and recovery command', () => {
      const configPath = '/home/user/.config/vaultkeeper/config.json'
      const err = new ConfigParseError(
        `Failed to parse config file at ${configPath} at line 3, column 12: Unexpected token. ` +
          "Fix the file — either install @vaultkeeper/cli and run 'vaultkeeper config init --force' " +
          'to overwrite it with a valid config, or repair/replace it programmatically via this ' +
          'library (pass an explicit `config` or `configDir`, or write a valid config.json yourself).',
        configPath,
        'line 3, column 12',
      )

      const formatted = formatError(err, CONFIG_DIR)

      expect(formatted).toContain(configPath)
      expect(formatted).toContain('vaultkeeper config init --force')
      expect(formatted).not.toContain('install @vaultkeeper/cli')
      expect(formatted).not.toContain('programmatically')
    })

    it('rewrites ConfigValidationError to a CLI-native message naming the path and recovery command', () => {
      const configPath = '/home/user/.config/vaultkeeper/config.json'
      const err = new ConfigValidationError(
        `Invalid config at ${configPath}: backends[0].type must be a non-empty string. ` +
          "Fix the file — either install @vaultkeeper/cli and run 'vaultkeeper config init --force' " +
          'to overwrite it with a valid config, or repair/replace it programmatically via this ' +
          'library (pass an explicit `config` or `configDir`, or write a valid config.json yourself).',
        'backends[0].type',
        configPath,
      )

      const formatted = formatError(err, CONFIG_DIR)

      expect(formatted).toContain(configPath)
      expect(formatted).toContain('vaultkeeper config init --force')
      expect(formatted).not.toContain('install @vaultkeeper/cli')
      expect(formatted).not.toContain('programmatically')
    })

    it('falls back to configDir when ConfigValidationError.configFilePath is undefined', () => {
      // configFilePath is undefined when the error came from validating an
      // in-memory value rather than a loaded file. The CLI never triggers
      // this path itself (it only validates via loadConfig), but formatError
      // must still produce a message naming a file path per AC3.
      const err = new ConfigValidationError('backends must be a non-empty array', 'backends')

      const formatted = formatError(err, CONFIG_DIR)

      expect(formatted).toContain(path.join(CONFIG_DIR, 'config.json'))
      expect(formatted).toContain('vaultkeeper config init --force')
    })
  })

  /** Build a Node.js-shaped filesystem error with a `code` (e.g. 'EACCES'). */
  function fsError(code: string, message: string): NodeJS.ErrnoException {
    return Object.assign(new Error(message), { code })
  }

  // Issue #137: an unreadable config.json (EACCES/EPERM) throws
  // FilesystemError, not ConfigParseError/ConfigValidationError, so #129/#114's
  // fix didn't cover it — formatError fell through to the generic `Error`
  // branch and printed the library's own message, still naming
  // "install @vaultkeeper/cli". This must get its own CLI-native remediation
  // that names the path, never suggests `config init --force` (that would
  // hit the same permission error trying to write the replacement file), and
  // points at checking permissions instead.
  describe('unreadable config.json gets a CLI-native remediation (issue #137)', () => {
    it('rewrites a read FilesystemError with no errno code (pre-#141 shape) to permissions wording, conservatively', () => {
      const configPath = path.join(CONFIG_DIR, 'config.json')
      const err = new FilesystemError(
        `Cannot read config file at ${configPath}: permission denied. ` +
          "Fix the file — either install @vaultkeeper/cli and run 'vaultkeeper config init --force' " +
          'to overwrite it with a valid config, or repair/replace it programmatically via this ' +
          'library (pass an explicit `config` or `configDir`, or write a valid config.json yourself).',
        configPath,
        'read',
      )

      const formatted = formatError(err, CONFIG_DIR)

      expect(formatted).toContain(configPath)
      expect(formatted).not.toContain('install @vaultkeeper/cli')
      expect(formatted).not.toContain('config init --force')
      expect(formatted.toLowerCase()).toContain('permission')
    })

    // Review follow-up (issue #137, PR #158): FilesystemError.code (added in
    // #141) lets the CLI distinguish an actual permission failure (EACCES,
    // EPERM) from any other read errno — a genuine permission code keeps the
    // permissions wording.
    it('rewrites an EACCES-coded FilesystemError to permissions wording', () => {
      const configPath = path.join(CONFIG_DIR, 'config.json')
      const err = new FilesystemError(
        `Cannot read config file at ${configPath}: permission denied.`,
        configPath,
        'read',
        fsError('EACCES', 'permission denied'),
      )

      const formatted = formatError(err, CONFIG_DIR)

      expect(formatted).toContain(configPath)
      expect(formatted.toLowerCase()).toContain('permission')
      expect(formatted).not.toContain('install @vaultkeeper/cli')
      expect(formatted).not.toContain('config init --force')
    })

    // Review follow-up (issue #137, PR #158): isUnreadableConfigFile matches
    // *any* read-path FilesystemError on config.json, including non-permission
    // failures like EISDIR (e.g. config.json is actually a directory). The
    // old unconditional "the current user cannot read it" wording would be a
    // wrong diagnosis here — the message must instead name the actual errno
    // and avoid the permissions claim it can't back up.
    it('rewrites an EISDIR-coded FilesystemError to honest, code-naming wording (not a permissions claim)', () => {
      const configPath = path.join(CONFIG_DIR, 'config.json')
      const err = new FilesystemError(
        `Cannot read config file at ${configPath}: EISDIR.`,
        configPath,
        'read',
        fsError('EISDIR', 'illegal operation on a directory'),
      )

      const formatted = formatError(err, CONFIG_DIR)

      expect(formatted).toContain(configPath)
      expect(formatted).toContain('EISDIR')
      expect(formatted.toLowerCase()).not.toContain('permission')
      expect(formatted).not.toContain('install @vaultkeeper/cli')
      expect(formatted).not.toContain('config init --force')
    })

    // Review follow-up (PR #158): an earlier draft suggested `ls -l <path>`
    // as an example command — POSIX-only (confusing on the Windows dpapi
    // backend) and an unquoted path that breaks on spaces/metacharacters
    // (e.g. a user-supplied --config-dir). The message must stay
    // platform-neutral prose with no embedded shell command.
    it('does not embed a POSIX-only shell command example (e.g. `ls -l`) in the remediation', () => {
      const configPath = path.join(CONFIG_DIR, 'config.json')
      const err = new FilesystemError(
        `Cannot read config file at ${configPath}: permission denied.`,
        configPath,
        'read',
      )

      const formatted = formatError(err, CONFIG_DIR)

      expect(formatted).not.toContain('ls -l')
      expect(formatted).not.toContain('`ls')
    })

    it('does not intercept a FilesystemError for a write failure on config.json', () => {
      // Only a 'read' permission failure on config.json is the config-read
      // path; other permissions (or other paths) fall through to the
      // generic Error branch unchanged.
      const configPath = path.join(CONFIG_DIR, 'config.json')
      const err = new FilesystemError(
        `Cannot write config file at ${configPath}: EACCES`,
        configPath,
        'write',
      )

      const formatted = formatError(err, CONFIG_DIR)

      expect(formatted).toBe(`FilesystemError: Cannot write config file at ${configPath}: EACCES`)
    })

    it('does not intercept a read-permission FilesystemError for a different path (e.g. a backend secret file)', () => {
      // FileBackend secret reads never live at configDir/config.json, but
      // guard the boundary explicitly so a future refactor can't silently
      // widen this to swallow unrelated read failures.
      const secretPath = path.join(CONFIG_DIR, 'secrets', 'db-password.json')
      const err = new FilesystemError(
        `Cannot read secret file at ${secretPath}: permission denied.`,
        secretPath,
        'read',
      )

      const formatted = formatError(err, CONFIG_DIR)

      expect(formatted).toBe(
        `FilesystemError: Cannot read secret file at ${secretPath}: permission denied.`,
      )
    })
  })

  // Regression: issue #118 — exec and delete previously worded their
  // SecretNotFoundError differently and neither included a recovery hint.
  // secretNotFoundMessage() is the single source of that wording, used by
  // both commands, so they can never drift apart again.
  describe('secretNotFoundMessage (issue #118)', () => {
    it('names the secret, the backend, and an actionable recovery hint', () => {
      const message = secretNotFoundMessage('db-password', 'file')
      expect(message).toBe(
        'Secret "db-password" not found in the "file" backend. ' +
          "Run `vaultkeeper store --name 'db-password'` to create it.",
      )
    })

    it('formats as a proper SecretNotFoundError via formatError', () => {
      const err = new SecretNotFoundError(secretNotFoundMessage('db-password', 'keychain'))
      const formatted = formatError(err, CONFIG_DIR)
      expect(formatted).toBe(
        'SecretNotFoundError: Secret "db-password" not found in the "keychain" backend. ' +
          "Run `vaultkeeper store --name 'db-password'` to create it.",
      )
    })

    // Regression (review follow-up, issue #118): `exec --secret` is only
    // validated for non-emptiness, not restricted to store/delete's safe
    // `--name` character set, so a secret name can contain a literal
    // double quote. Unescaped interpolation would unbalance the quotes
    // around the name in the diagnostic sentence; JSON.stringify() escapes
    // it there instead.
    it('escapes a double quote in the secret name instead of unbalancing the surrounding quotes', () => {
      const message = secretNotFoundMessage('foo"bar', 'file')
      expect(message).toBe(
        'Secret "foo\\"bar" not found in the "file" backend. ' +
          `Run \`vaultkeeper store --name 'foo"bar'\` to create it.`,
      )
    })

    // Regression (review follow-up, issue #118): the recovery hint is a
    // literal shell command a user may copy and paste. An unescaped name
    // containing a double quote would leave that pasted command in an
    // unterminated-quote state; shellQuote() (single-quote POSIX escaping)
    // keeps the hint syntactically safe regardless of the name's content.
    it('shell-quotes the secret name in the recovery hint so it stays copy/pasteable', () => {
      const message = secretNotFoundMessage("weird'name", 'file')
      // shellQuote("weird'name") -> 'weird'\''name' (POSIX single-quote escaping)
      expect(message).toContain("vaultkeeper store --name 'weird'\\''name'")
    })
  })
})

// Issue #130: `doctor`'s config preflight check carries structured error
// context (PreflightCheckError) rather than only prose, so the CLI builds the
// same CLI-native remediation for doctor that formatError builds for every
// other command — never the library's "install @vaultkeeper/cli" text.
describe('formatPreflightConfigError', () => {
  const configPath = '/home/user/.config/vaultkeeper/config.json'

  it('builds a CLI-native remediation with the path and parse location for a config-parse failure', () => {
    const error: PreflightCheckError = {
      kind: 'config-parse',
      configPath,
      location: 'line 3, column 12',
    }

    const formatted = formatPreflightConfigError(error)

    expect(formatted).toContain(configPath)
    expect(formatted).toContain('(at line 3, column 12)')
    expect(formatted).toContain('vaultkeeper config init --force')
    expect(formatted).not.toContain('install @vaultkeeper/cli')
  })

  it('omits the location suffix for a config-validation failure', () => {
    const error: PreflightCheckError = { kind: 'config-validation', configPath }

    const formatted = formatPreflightConfigError(error)

    expect(formatted).toContain(configPath)
    expect(formatted).not.toContain('(at ')
    expect(formatted).toContain('vaultkeeper config init --force')
    expect(formatted).not.toContain('install @vaultkeeper/cli')
  })

  it('shares the exact remediation wording with formatError for a config-parse failure (one voice across commands)', () => {
    const err = new ConfigParseError(
      `Failed to parse config file at ${configPath} at line 3, column 12: bad. ` +
        'install @vaultkeeper/cli and run ...',
      configPath,
      'line 3, column 12',
    )
    // formatError prefixes the error name; the core sentence must match.
    const errorPath = formatError(err, CONFIG_DIR)
    const doctorPath = formatPreflightConfigError({
      kind: 'config-parse',
      configPath,
      location: 'line 3, column 12',
    })

    expect(errorPath).toBe(`ConfigParseError: ${doctorPath}`)
  })

  // Issue #137: formatError now includes ConfigValidationError.field in its
  // message (e.g. "is invalid (`version`)"), giving CLI users back the
  // field-level detail #129 dropped. The doctor path's PreflightCheckError
  // deliberately does NOT gain a `field` — extending that structured type is
  // an explicit non-goal of #137 (see #130/#145's shipped design) — so the
  // two paths diverge here rather than sharing wording exactly.
  it('includes the failing field in formatError but not in the doctor path (issue #137, non-goal boundary)', () => {
    const err = new ConfigValidationError(
      `Invalid config at ${configPath}: bad. install @vaultkeeper/cli and run ...`,
      'version',
      configPath,
    )
    const errorPath = formatError(err, CONFIG_DIR)
    const doctorPath = formatPreflightConfigError({ kind: 'config-validation', configPath })

    expect(errorPath).toBe(
      `ConfigValidationError: The config at \`${configPath}\` is invalid (\`version\`) — ` +
        'run `vaultkeeper config init --force` to overwrite it.',
    )
    expect(doctorPath).toBe(
      `The config at \`${configPath}\` is invalid — run \`vaultkeeper config init --force\` to overwrite it.`,
    )
  })
})
