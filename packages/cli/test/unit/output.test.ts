import { describe, it, expect } from 'vitest'
import * as path from 'node:path'
import { ConfigParseError, ConfigValidationError, SecretNotFoundError } from 'vaultkeeper'
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

  // Regression: issue #118 — exec and delete previously worded their
  // SecretNotFoundError differently and neither included a recovery hint.
  // secretNotFoundMessage() is the single source of that wording, used by
  // both commands, so they can never drift apart again.
  describe('secretNotFoundMessage (issue #118)', () => {
    it('names the secret, the backend, and an actionable recovery hint', () => {
      const message = secretNotFoundMessage('db-password', 'file')
      expect(message).toBe(
        'Secret "db-password" not found in the "file" backend. ' +
          'Run `vaultkeeper store --name db-password` to create it.',
      )
    })

    it('formats as a proper SecretNotFoundError via formatError', () => {
      const err = new SecretNotFoundError(secretNotFoundMessage('db-password', 'keychain'))
      const formatted = formatError(err, CONFIG_DIR)
      expect(formatted).toBe(
        'SecretNotFoundError: Secret "db-password" not found in the "keychain" backend. ' +
          'Run `vaultkeeper store --name db-password` to create it.',
      )
    })

    // Regression (review follow-up, issue #118): `exec --secret` is only
    // validated for non-emptiness, not restricted to store/delete's safe
    // `--name` character set, so a secret name can contain a literal
    // double quote. Unescaped interpolation would unbalance the quotes
    // around the name; JSON.stringify() escapes it instead.
    it('escapes a double quote in the secret name instead of unbalancing the surrounding quotes', () => {
      const message = secretNotFoundMessage('foo"bar', 'file')
      expect(message).toBe(
        'Secret "foo\\"bar" not found in the "file" backend. ' +
          'Run `vaultkeeper store --name foo"bar` to create it.',
      )
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

  it('shares the exact remediation wording with formatError (one voice across commands)', () => {
    const err = new ConfigValidationError(
      `Invalid config at ${configPath}: bad. install @vaultkeeper/cli and run ...`,
      'version',
      configPath,
    )
    // formatError prefixes the error name; the core sentence must match.
    const errorPath = formatError(err, CONFIG_DIR)
    const doctorPath = formatPreflightConfigError({ kind: 'config-validation', configPath })

    expect(errorPath).toBe(`ConfigValidationError: ${doctorPath}`)
  })
})
