import { describe, it, expect } from 'vitest'
import * as path from 'node:path'
import {
  ConfigParseError,
  ConfigValidationError,
  FilesystemError,
  SecretNotFoundError,
  getPlatformDefaultConfigDir,
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

    it('does not route a write failure on config.json through the config-read remediation', () => {
      // Only a 'read' permission failure on config.json is the config-read
      // path; a 'write' failure is not intercepted by isUnreadableConfigFile.
      // It still gets the general polished FilesystemError message (#150) —
      // never the config-read wording and never raw OS text.
      const configPath = path.join(CONFIG_DIR, 'config.json')
      const err = new FilesystemError(
        `Cannot write config file at ${configPath}: EACCES`,
        configPath,
        'write',
      )

      const formatted = formatError(err, CONFIG_DIR)

      expect(formatted).toBe(
        `FilesystemError: The file at \`${configPath}\` cannot be written (permission denied). ` +
          "Check the file's permissions and try again.",
      )
      // Not the config-read remediation, and no raw OS fragment leaks through.
      expect(formatted).not.toContain('ownership')
      expect(formatted).not.toContain('EACCES')
    })

    it('does not route a read-permission FilesystemError for a different path (e.g. a backend secret file) through the config-read remediation', () => {
      // FileBackend secret reads never live at configDir/config.json, but
      // guard the boundary explicitly so a future refactor can't silently
      // widen the config-read branch to swallow unrelated read failures. Such
      // an error still gets the general polished FilesystemError message
      // (#150), not raw OS text and not the config-read wording.
      const secretPath = path.join(CONFIG_DIR, 'secrets', 'db-password.json')
      const err = new FilesystemError(
        `Cannot read secret file at ${secretPath}: permission denied.`,
        secretPath,
        'read',
      )

      const formatted = formatError(err, CONFIG_DIR)

      expect(formatted).toBe(
        `FilesystemError: The file at \`${secretPath}\` could not be read. ` +
          "Check the path and the file's permissions, then try again.",
      )
      // Not the config-read remediation (its "ownership" wording is unique).
      expect(formatted).not.toContain('ownership')
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
  const configDir = '/home/user/.config/vaultkeeper'
  const configPath = path.join(configDir, 'config.json')

  it('builds a CLI-native remediation with the path and parse location for a config-parse failure', () => {
    const error: PreflightCheckError = {
      kind: 'config-parse',
      configPath,
      location: 'line 3, column 12',
    }

    const formatted = formatPreflightConfigError(error, configDir)

    expect(formatted).toContain(configPath)
    expect(formatted).toContain('(at line 3, column 12)')
    expect(formatted).toContain('vaultkeeper config init --force')
    expect(formatted).not.toContain('install @vaultkeeper/cli')
  })

  it('omits the location suffix for a config-validation failure', () => {
    const error: PreflightCheckError = { kind: 'config-validation', configPath }

    const formatted = formatPreflightConfigError(error, configDir)

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
    // Both surfaces get the same active dir, so any --config-dir suffix is
    // identical on both sides and the equality still holds.
    const errorPath = formatError(err, CONFIG_DIR)
    const doctorPath = formatPreflightConfigError(
      {
        kind: 'config-parse',
        configPath,
        location: 'line 3, column 12',
      },
      CONFIG_DIR,
    )

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
    // Pass the platform-default dir so the recovery command stays bare here —
    // this test's focus is the field detail (#137), while the --config-dir
    // behavior (#149) is covered by its own dedicated cases below.
    const defaultDir = getPlatformDefaultConfigDir()
    const errorPath = formatError(err, defaultDir)
    const doctorPath = formatPreflightConfigError(
      { kind: 'config-validation', configPath },
      defaultDir,
    )

    expect(errorPath).toBe(
      `ConfigValidationError: The config at \`${configPath}\` is invalid (\`version\`) — ` +
        'run `vaultkeeper config init --force` to overwrite it.',
    )
    expect(doctorPath).toBe(
      `The config at \`${configPath}\` is invalid — run \`vaultkeeper config init --force\` to overwrite it.`,
    )
  })
})

// Issue #149: when a non-default config dir is active, the printed recovery
// command must carry an explicit `--config-dir` so a copy-paste into a fresh
// shell repairs the exact diagnosed file rather than writing a fresh config to
// the platform default and leaving the corrupt file untouched. Keyed off the
// env-INDEPENDENT platform default so a dir that came only from
// VAULTKEEPER_CONFIG_DIR still gets an explicit flag.
describe('config remediation carries --config-dir for a non-default dir (issue #149)', () => {
  const platformDefault = getPlatformDefaultConfigDir()

  it('emits a bare `config init --force` when the active dir IS the platform default', () => {
    const configPath = path.join(platformDefault, 'config.json')
    const error: PreflightCheckError = { kind: 'config-validation', configPath }

    const formatted = formatPreflightConfigError(error, platformDefault)

    expect(formatted).toContain('run `vaultkeeper config init --force` to overwrite it.')
    // The default-dir case must never leak a path into the command.
    expect(formatted).not.toContain('--config-dir')
  })

  // Review edge case (issue #149): the default-dir check must compare
  // normalized paths, so a differently-spelled-but-equivalent form of the
  // default dir is still recognized as default and stays bare.
  it('treats a trailing-slash spelling of the default dir as default (no --config-dir)', () => {
    const withSlash = platformDefault + path.sep
    const configPath = path.join(platformDefault, 'config.json')
    const error: PreflightCheckError = { kind: 'config-validation', configPath }

    const formatted = formatPreflightConfigError(error, withSlash)

    expect(formatted).toContain('run `vaultkeeper config init --force` to overwrite it.')
    expect(formatted).not.toContain('--config-dir')
  })

  it('treats a non-normalized relative spelling of the default dir as default (no --config-dir)', () => {
    // path.resolve() collapses this back to the same absolute default dir.
    const relForm = path.relative(process.cwd(), platformDefault)
    const configPath = path.join(platformDefault, 'config.json')
    const error: PreflightCheckError = { kind: 'config-validation', configPath }

    const formatted = formatPreflightConfigError(error, relForm)

    expect(formatted).toContain('run `vaultkeeper config init --force` to overwrite it.')
    expect(formatted).not.toContain('--config-dir')
  })

  it('appends `--config-dir <dir>` when a non-default dir is active (flag case)', () => {
    const altDir = '/tmp/vk-alt'
    const configPath = path.join(altDir, 'config.json')
    const error: PreflightCheckError = { kind: 'config-validation', configPath }

    const formatted = formatPreflightConfigError(error, altDir)

    expect(formatted).toContain(
      "run `vaultkeeper config init --force --config-dir '/tmp/vk-alt'` to overwrite it.",
    )
  })

  it('shell-quotes a non-default dir containing spaces/metacharacters', () => {
    const altDir = "/tmp/weird dir/it's"
    const configPath = path.join(altDir, 'config.json')
    const error: PreflightCheckError = { kind: 'config-validation', configPath }

    const formatted = formatPreflightConfigError(error, altDir)

    // shellQuote wraps in single quotes and escapes an embedded quote as '\''.
    expect(formatted).toContain("--config-dir '/tmp/weird dir/it'\\''s'")
  })

  it('also appends --config-dir on the formatError (config-parse) path', () => {
    const altDir = '/tmp/vk-alt'
    const configPath = path.join(altDir, 'config.json')
    const err = new ConfigParseError('parse failed', configPath, 'line 1, column 1')

    const formatted = formatError(err, altDir)

    expect(formatted).toContain("--config-dir '/tmp/vk-alt'")
    expect(formatted).toContain('(at line 1, column 1)')
  })
})

// Issue #150: FilesystemError must render a human message from its typed
// fields — plainly stating missing vs permission-denied plus a next step —
// and must never echo the raw Node `ENOENT: … open '<path>'` fragment.
describe('formatError renders FilesystemError without raw OS text (issue #150)', () => {
  it('renders a missing file (ENOENT) as a plain does-not-exist message with a next step', () => {
    const p = '/nonexistent/path/to/tool'
    const err = new FilesystemError(
      `Cannot read executable at ${p}: ENOENT: no such file or directory, open '${p}'`,
      p,
      'read',
    )

    const formatted = formatError(err, CONFIG_DIR)

    expect(formatted).toBe(
      `FilesystemError: The file at \`${p}\` does not exist. ` +
        'Check that the path is correct and the file exists, then try again.',
    )
    // No raw Node fragment leaks through.
    expect(formatted).not.toContain('ENOENT')
    expect(formatted).not.toContain(`open '`)
  })

  it('renders a permission-denied file (EACCES) as a plain permission message with a next step', () => {
    const p = '/tmp/noperm'
    const err = new FilesystemError(
      `Cannot read executable at ${p}: EACCES: permission denied, open '${p}'`,
      p,
      'read',
    )

    const formatted = formatError(err, CONFIG_DIR)

    expect(formatted).toBe(
      `FilesystemError: The file at \`${p}\` cannot be read (permission denied). ` +
        "Check the file's permissions and try again.",
    )
    expect(formatted).not.toContain('EACCES')
    expect(formatted).not.toContain(`open '`)
  })

  it('uses the past-tense operation verb from the permission field for a write EACCES', () => {
    const p = '/tmp/readonly/secret.json'
    const err = new FilesystemError(
      `Failed to write secret file at ${p}: EACCES: permission denied, open '${p}'`,
      p,
      'write',
    )

    const formatted = formatError(err, CONFIG_DIR)

    expect(formatted).toContain('cannot be written (permission denied)')
    expect(formatted).not.toContain(`open '`)
  })

  // FileBackend throws `permission: 'rwx'` when it can't create its storage
  // directory — a permission SET, not an operation verb. It must still read
  // as the operation that failed (created), not the generic "accessed".
  it("renders a storage-directory creation failure (permission 'rwx') as 'created'", () => {
    const dir = '/tmp/vk-store/secrets'
    const err = new FilesystemError(`Failed to create storage directory: ${dir}: EACCES`, dir, 'rwx')

    const formatted = formatError(err, CONFIG_DIR)

    expect(formatted).toBe(
      `FilesystemError: The file at \`${dir}\` cannot be created (permission denied). ` +
        "Check the file's permissions and try again.",
    )
    expect(formatted).not.toContain('accessed')
    expect(formatted).not.toContain('EACCES')
  })

  it('falls back to a clean generic message for an unrecognized OS code', () => {
    const p = '/tmp/busy'
    const err = new FilesystemError(`Failed to read at ${p}: EBUSY: resource busy`, p, 'read')

    const formatted = formatError(err, CONFIG_DIR)

    expect(formatted).toBe(
      `FilesystemError: The file at \`${p}\` could not be read. ` +
        "Check the path and the file's permissions, then try again.",
    )
    expect(formatted).not.toContain('EBUSY')
  })
})
