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

    it("defaults to the access context (equivalent to passing 'access')", () => {
      expect(secretNotFoundMessage('db-password', 'file')).toBe(
        secretNotFoundMessage('db-password', 'file', 'access'),
      )
    })

    // Issue #183: on the delete path, suggesting `store` to CREATE the secret
    // the user is deleting is nonsensical. The delete context shares the
    // diagnostic line but gives a neutral, non-creating hint.
    describe('delete context (issue #183)', () => {
      it('shares the diagnostic line but suggests no creation and names no store command', () => {
        const message = secretNotFoundMessage('db-password', 'file', 'delete')
        expect(message).toBe(
          'Secret "db-password" not found in the "file" backend. ' +
            'It may have already been deleted, or the name may be misspelled.',
        )
      })

      it('never tells the user to store/create the secret being deleted', () => {
        const message = secretNotFoundMessage('db-password', 'file', 'delete')
        expect(message).not.toContain('to create it')
        expect(message).not.toContain('vaultkeeper store')
      })

      it('formats as a proper SecretNotFoundError via formatError', () => {
        const err = new SecretNotFoundError(
          secretNotFoundMessage('db-password', 'keychain', 'delete'),
        )
        expect(formatError(err, CONFIG_DIR)).toBe(
          'SecretNotFoundError: Secret "db-password" not found in the "keychain" backend. ' +
            'It may have already been deleted, or the name may be misspelled.',
        )
      })
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

  // Issue #215: an unknown backend type gets the same "valid types" guidance
  // the runtime BackendUnavailableError gives, so doctor names both the
  // offending type and the valid options rather than a bare "invalid".
  it('names the offending type and lists the valid options for a config-unknown-backend failure', () => {
    const error: PreflightCheckError = {
      kind: 'config-unknown-backend',
      configPath,
      field: 'backends[0].type',
      backendType: 'not-a-real-backend',
      knownBackendTypes: ['file', 'keychain', 'dpapi', 'secret-tool', '1password', 'yubikey'],
    }

    const formatted = formatPreflightConfigError(error, configDir)

    expect(formatted).toContain(configPath)
    expect(formatted).toContain('not-a-real-backend')
    // The valid options mirror the runtime BackendUnavailableError guidance.
    expect(formatted).toContain('file, keychain, dpapi, secret-tool, 1password, yubikey')
    expect(formatted).toContain('vaultkeeper config init --force')
    expect(formatted).not.toContain('install @vaultkeeper/cli')
  })

  it('still names the bad type and recovery command when known types are absent', () => {
    const error: PreflightCheckError = {
      kind: 'config-unknown-backend',
      configPath,
      field: 'backends[0].type',
      backendType: 'nope',
    }

    const formatted = formatPreflightConfigError(error, configDir)

    expect(formatted).toContain('nope')
    expect(formatted).toContain('vaultkeeper config init --force')
  })

  // Issue #169: a config-read failure (config file unreadable, e.g. EACCES on
  // the file or its parent dir) has a different remediation from parse/
  // validation — `config init --force` cannot fix a read-permission problem —
  // so the doctor remediation points at the file's permissions instead.
  it('builds a permissions remediation (not `config init --force`) for an EACCES-coded config-read failure', () => {
    const error: PreflightCheckError = { kind: 'config-read', configPath, code: 'EACCES' }

    const formatted = formatPreflightConfigError(error, configDir)

    expect(formatted).toContain(configPath)
    expect(formatted.toLowerCase()).toContain('permission')
    expect(formatted).toContain('could not be read')
    expect(formatted).not.toContain('config init --force')
    expect(formatted).not.toContain('install @vaultkeeper/cli')
  })

  it('treats a config-read failure with no errno code conservatively as a permissions problem', () => {
    const error: PreflightCheckError = { kind: 'config-read', configPath, code: undefined }

    const formatted = formatPreflightConfigError(error, configDir)

    expect(formatted).toContain(configPath)
    expect(formatted.toLowerCase()).toContain('permission')
    expect(formatted).not.toContain('config init --force')
  })

  it('names the errno instead of claiming permissions for a non-permission config-read failure (EISDIR)', () => {
    const error: PreflightCheckError = { kind: 'config-read', configPath, code: 'EISDIR' }

    const formatted = formatPreflightConfigError(error, configDir)

    expect(formatted).toContain(configPath)
    expect(formatted).toContain('EISDIR')
    expect(formatted.toLowerCase()).not.toContain('permission')
    expect(formatted).not.toContain('config init --force')
  })

  // The doctor `config-read` remediation must match the core sentence
  // formatError produces for the same unreadable `config.json`, so doctor and
  // every other command speak with one voice (formatError just prefixes the
  // error name).
  it('shares the exact read-error wording with formatError (one voice across commands)', () => {
    const err = new FilesystemError(
      `Cannot read config file at ${configPath}: permission denied.`,
      configPath,
      'read',
      Object.assign(new Error('permission denied'), { code: 'EACCES' }),
    )
    const errorPath = formatError(err, configDir)
    const doctorPath = formatPreflightConfigError(
      { kind: 'config-read', configPath, code: 'EACCES' },
      configDir,
    )

    expect(errorPath).toBe(`FilesystemError: ${doctorPath}`)
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

  // Issue #202: the doctor path now surfaces the validation `field` the same
  // way `formatError` does (reversing the #137 non-goal). A config-validation
  // PreflightCheckError carrying `field` renders "is invalid (`version`)", so
  // doctor and every other command name the same failing field with one voice
  // — the validation analogue of how a parse failure surfaces its `location`.
  it('includes the failing field in BOTH formatError and the doctor path (issue #202)', () => {
    const err = new ConfigValidationError(
      `Invalid config at ${configPath}: bad. install @vaultkeeper/cli and run ...`,
      'version',
      configPath,
    )
    // Pass the platform-default dir so the recovery command stays bare here —
    // this test's focus is the field detail, while the --config-dir behavior
    // (#149) is covered by its own dedicated cases below.
    const defaultDir = getPlatformDefaultConfigDir()
    const errorPath = formatError(err, defaultDir)
    const doctorPath = formatPreflightConfigError(
      { kind: 'config-validation', configPath, field: 'version' },
      defaultDir,
    )

    const expected =
      `The config at \`${configPath}\` is invalid (\`version\`) — ` +
      'run `vaultkeeper config init --force` to overwrite it.'
    expect(doctorPath).toBe(expected)
    // One voice: formatError just prefixes the error name onto the same text.
    expect(errorPath).toBe(`ConfigValidationError: ${expected}`)
  })

  // A config-validation PreflightCheckError with no `field` (e.g. an older
  // producer, or a validation failure that carries no field path) omits the
  // parenthetical detail rather than rendering an empty `()`.
  it('omits the field detail for a config-validation failure carrying no field', () => {
    const doctorPath = formatPreflightConfigError(
      { kind: 'config-validation', configPath },
      configDir,
    )

    // No field → the invalid clause carries no parenthetical detail (no empty
    // `()`), unlike the field-bearing case above which renders "(`version`)".
    expect(doctorPath).toContain(`The config at \`${configPath}\` is invalid — run`)
    expect(doctorPath).not.toContain('is invalid (')
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

  // The typed `code` field is the contract (FilesystemError.code says to
  // prefer it over parsing the message). These prove code wins even when the
  // message text carries a DIFFERENT/absent token, so classification can't be
  // fooled by wording changes or a path that incidentally contains a token.
  it('classifies by err.code (EACCES) even when the message contains no errno token', () => {
    const p = '/tmp/secret.json'
    const err = new FilesystemError(
      // Deliberately no "EACCES"/"ENOENT" in the message text.
      `Could not open ${p}`,
      p,
      'read',
      Object.assign(new Error('boom'), { code: 'EACCES' }),
    )

    const formatted = formatError(err, CONFIG_DIR)

    expect(formatted).toBe(
      `FilesystemError: The file at \`${p}\` cannot be read (permission denied). ` +
        "Check the file's permissions and try again.",
    )
  })

  it('classifies by err.code (ENOENT) even when the message says something else', () => {
    // Message text mentions EACCES, but the typed code is ENOENT — code wins.
    const p = '/tmp/gone'
    const err = new FilesystemError(
      `EACCES-looking prose about ${p}`,
      p,
      'read',
      Object.assign(new Error('missing'), { code: 'ENOENT' }),
    )

    const formatted = formatError(err, CONFIG_DIR)

    expect(formatted).toBe(
      `FilesystemError: The file at \`${p}\` does not exist. ` +
        'Check that the path is correct and the file exists, then try again.',
    )
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
  // as a DIRECTORY-creation failure: 'rwx' is FileBackend's legacy label for
  // the same failure class as 'create' (its storage-dir mkdir), so it gets the
  // same directory-oriented wording (review follow-up on issue #228).
  it("renders a storage-directory creation failure (permission 'rwx') with the directory wording", () => {
    const dir = '/tmp/vk-store/secrets'
    const err = new FilesystemError(
      `Failed to create storage directory: ${dir}: EACCES`,
      dir,
      'rwx',
    )

    const formatted = formatError(err, CONFIG_DIR)

    // The storage dir lives outside the config dir, so the --config-dir
    // relocation hint would be misleading and must be omitted.
    expect(formatted).toBe(
      `FilesystemError: The directory at \`${dir}\` could not be created (permission denied). ` +
        'Check that its parent directory is writable, then try again.',
    )
    expect(formatted).not.toContain('--config-dir')
    expect(formatted).not.toContain('accessed')
    expect(formatted).not.toContain('EACCES')
  })

  // Config-dir CREATION failures (`config init` / first `store`) use
  // `permission: 'create'` and must read as a DIRECTORY that could not be
  // created, with a parent-directory fix hint — not the file-oriented wording
  // above (issue #228).
  it("renders a config-dir creation EACCES (permission 'create') as a directory + parent hint", () => {
    const dir = '/tmp/readonly/sub'
    const cause = Object.assign(new Error("EACCES: permission denied, mkdir '/tmp/readonly/sub'"), {
      code: 'EACCES',
    })
    const err = new FilesystemError(
      `Failed to create config directory at ${dir}: ${cause.message}`,
      dir,
      'create',
      cause,
    )

    // In the real flow the failing path IS the config dir formatError
    // receives, so pass it as such — that is what makes the --config-dir
    // relocation hint applicable.
    const formatted = formatError(err, dir)

    expect(formatted).toBe(
      `FilesystemError: The directory at \`${dir}\` could not be created (permission denied). ` +
        'Check that its parent directory is writable, or choose a writable location with --config-dir, then try again.',
    )
    expect(formatted).not.toContain('EACCES')
    expect(formatted).not.toContain('mkdir')
    // Directory wording, never "The file at".
    expect(formatted).not.toContain('The file at')
  })

  it("renders a non-permission config-dir creation failure (permission 'create') without a permission claim", () => {
    const dir = '/tmp/readonly/sub'
    const cause = Object.assign(new Error('EROFS: read-only file system'), { code: 'EROFS' })
    const err = new FilesystemError(
      `Failed to create config directory at ${dir}: ${cause.message}`,
      dir,
      'create',
      cause,
    )

    const formatted = formatError(err, CONFIG_DIR)

    expect(formatted).toBe(
      `FilesystemError: The directory at \`${dir}\` could not be created. ` +
        'Check that its parent directory exists and is writable, then try again.',
    )
    expect(formatted).not.toContain('permission denied')
    expect(formatted).not.toContain('EROFS')
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
