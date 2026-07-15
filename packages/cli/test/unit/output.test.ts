import { describe, it, expect } from 'vitest'
import * as path from 'node:path'
import { ConfigParseError, ConfigValidationError } from 'vaultkeeper'
import { formatError } from '../../src/output.js'

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
})
