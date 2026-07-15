import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import {
  validateConfig,
  loadConfig,
  getDefaultConfigDir,
  getPlatformDefaultConfigDir,
  defaultBackendType,
  platformNativeBackendType,
} from '../../src/config.js'
import { ConfigValidationError, ConfigParseError, FilesystemError } from '../../src/errors.js'

vi.mock('node:fs/promises', () => ({
  readFile: vi.fn(),
}))

// Must import after mock declaration
const { readFile } = await import('node:fs/promises')

/** Build a Node.js-shaped filesystem error with a `code` (e.g. 'ENOENT'). */
function fsError(code: string, message: string): NodeJS.ErrnoException {
  return Object.assign(new Error(message), { code })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function validConfigJson(): Record<string, unknown> {
  return {
    version: 1,
    backends: [{ type: 'file', enabled: true }],
    keyRotation: { gracePeriodDays: 7 },
    defaults: { ttlMinutes: 60, trustTier: 3 },
  }
}

// ---------------------------------------------------------------------------
// validateConfig
// ---------------------------------------------------------------------------

describe('validateConfig', () => {
  it('should accept a valid minimal config', () => {
    const result = validateConfig(validConfigJson())
    expect(result.version).toBe(1)
    expect(result.backends).toHaveLength(1)
    expect(result.defaults.ttlMinutes).toBe(60)
  })

  it('should accept config with developmentMode', () => {
    const input = { ...validConfigJson(), developmentMode: { executables: ['/usr/bin/node'] } }
    const result = validateConfig(input)
    expect(result.developmentMode?.executables).toEqual(['/usr/bin/node'])
  })

  it('should accept config with backend plugin and path', () => {
    const input = validConfigJson()
    input.backends = [{ type: 'custom', enabled: true, plugin: true, path: '/opt/plugin.js' }]
    const result = validateConfig(input)
    expect(result.backends[0]?.plugin).toBe(true)
    expect(result.backends[0]?.path).toBe('/opt/plugin.js')
  })

  it('should reject a whitespace-only backend path (regression: PR #78 review)', () => {
    // A path of " " previously passed validation and was treated as a real
    // storage directory by file-based backends instead of being rejected.
    const input = validConfigJson()
    input.backends = [{ type: 'file', enabled: true, path: ' ' }]
    expect(() => validateConfig(input)).toThrow(ConfigValidationError)
    expect(() => validateConfig(input)).toThrow('must not be empty or whitespace-only')
  })

  it('should reject an empty-string backend path', () => {
    const input = validConfigJson()
    input.backends = [{ type: 'file', enabled: true, path: '' }]
    expect(() => validateConfig(input)).toThrow(ConfigValidationError)
  })

  it('should reject a non-string backend path as ConfigValidationError (consistency: PR #78 review)', () => {
    // The adjacent type check for `path` previously threw a plain Error while
    // the whitespace check threw ConfigValidationError — both now agree.
    const input = validConfigJson()
    input.backends = [{ type: 'file', enabled: true, path: 42 }]
    expect(() => validateConfig(input)).toThrow(ConfigValidationError)
    expect(() => validateConfig(input)).toThrow('path must be a string')
  })

  it('should accept backend with valid options object', () => {
    const input = validConfigJson()
    input.backends = [
      { type: 'file', enabled: true, options: { region: 'us-east-1', vault: 'my-vault' } },
    ]
    const result = validateConfig(input)
    expect(result.backends[0]?.options).toEqual({ region: 'us-east-1', vault: 'my-vault' })
  })

  it('should accept backend without options (options is optional)', () => {
    const input = validConfigJson()
    // No options field — should parse fine
    const result = validateConfig(input)
    expect(result.backends[0]?.options).toBeUndefined()
  })

  it('should reject backend with non-object options', () => {
    const input = validConfigJson()
    input.backends = [{ type: 'file', enabled: true, options: 'not-an-object' }]
    expect(() => validateConfig(input)).toThrow('options must be an object')
  })

  it('should reject backend with options containing non-string values', () => {
    const input = validConfigJson()
    input.backends = [{ type: 'file', enabled: true, options: { count: 42 } }]
    expect(() => validateConfig(input)).toThrow('must be a string')
  })

  it('should report a bracketed, quoted field path for an invalid option value (PR #78 review)', () => {
    // Option keys are user-defined and may contain characters that aren't
    // valid identifier segments (dashes, spaces, dots); the field path must
    // bracket-and-quote the key rather than dot-append it.
    const input = validConfigJson()
    input.backends = [{ type: 'file', enabled: true, options: { 'weird key.name': 42 } }]
    try {
      validateConfig(input)
      expect.unreachable('validateConfig should have thrown')
    } catch (err) {
      if (!(err instanceof ConfigValidationError)) {
        throw err
      }
      expect(err.field).toBe('backends[0].options["weird key.name"]')
    }
  })

  // Negative tests
  it('should reject non-object', () => {
    expect(() => validateConfig('string')).toThrow(ConfigValidationError)
    expect(() => validateConfig('string')).toThrow('Config must be an object')
    expect(() => validateConfig(null)).toThrow('Config must be an object')
    expect(() => validateConfig(42)).toThrow('Config must be an object')
  })

  it('should reject wrong version', () => {
    expect(() => validateConfig({ ...validConfigJson(), version: 2 })).toThrow(
      ConfigValidationError,
    )
    expect(() => validateConfig({ ...validConfigJson(), version: 2 })).toThrow('version must be 1')
  })

  it('should reject empty backends', () => {
    expect(() => validateConfig({ ...validConfigJson(), backends: [] })).toThrow(
      'at least one backend',
    )
  })

  it('should reject backend with missing type', () => {
    expect(() => validateConfig({ ...validConfigJson(), backends: [{ enabled: true }] })).toThrow(
      ConfigValidationError,
    )
    expect(() => validateConfig({ ...validConfigJson(), backends: [{ enabled: true }] })).toThrow(
      'type must be a non-empty string',
    )
  })

  it('should reject backend with non-boolean enabled', () => {
    expect(() =>
      validateConfig({ ...validConfigJson(), backends: [{ type: 'file', enabled: 'yes' }] }),
    ).toThrow('enabled must be a boolean')
  })

  it('should reject invalid gracePeriodDays', () => {
    expect(() =>
      validateConfig({ ...validConfigJson(), keyRotation: { gracePeriodDays: -1 } }),
    ).toThrow('gracePeriodDays must be a positive number')
  })

  it('should reject invalid ttlMinutes', () => {
    expect(() =>
      validateConfig({
        ...validConfigJson(),
        defaults: { ttlMinutes: 0, trustTier: 3 },
      }),
    ).toThrow('ttlMinutes must be a positive number')
  })

  it('should reject invalid trustTier', () => {
    expect(() =>
      validateConfig({
        ...validConfigJson(),
        defaults: { ttlMinutes: 60, trustTier: 5 },
      }),
    ).toThrow('trustTier must be 1, 2, or 3')
  })

  // Rust CLI compatibility: trustTier is serialized as a string ("1"/"2"/"3")
  it('should accept numeric trustTier 3', () => {
    const result = validateConfig({
      ...validConfigJson(),
      defaults: { ttlMinutes: 60, trustTier: 3 },
    })
    expect(result.defaults.trustTier).toBe(3)
  })

  it('should accept string trustTier "3" and coerce it to the number 3', () => {
    const result = validateConfig({
      ...validConfigJson(),
      defaults: { ttlMinutes: 60, trustTier: '3' },
    })
    expect(result.defaults.trustTier).toBe(3)
  })

  it('should accept string trustTier "1" and coerce it to the number 1', () => {
    const result = validateConfig({
      ...validConfigJson(),
      defaults: { ttlMinutes: 60, trustTier: '1' },
    })
    expect(result.defaults.trustTier).toBe(1)
  })

  it('should accept string trustTier "2" and coerce it to the number 2', () => {
    const result = validateConfig({
      ...validConfigJson(),
      defaults: { ttlMinutes: 60, trustTier: '2' },
    })
    expect(result.defaults.trustTier).toBe(2)
  })

  it('should reject string trustTier "4" (out of range)', () => {
    expect(() =>
      validateConfig({
        ...validConfigJson(),
        defaults: { ttlMinutes: 60, trustTier: '4' },
      }),
    ).toThrow('trustTier must be 1, 2, or 3')
  })

  it('should reject non-numeric string trustTier "high"', () => {
    expect(() =>
      validateConfig({
        ...validConfigJson(),
        defaults: { ttlMinutes: 60, trustTier: 'high' },
      }),
    ).toThrow('trustTier must be 1, 2, or 3')
  })

  it('should reject non-array developmentMode.executables', () => {
    expect(() =>
      validateConfig({
        ...validConfigJson(),
        developmentMode: { executables: 'not-array' },
      }),
    ).toThrow('executables must be an array')
  })

  it('should reject non-string items in developmentMode.executables', () => {
    expect(() =>
      validateConfig({
        ...validConfigJson(),
        developmentMode: { executables: [123] },
      }),
    ).toThrow('must be a string')
  })
})

// ---------------------------------------------------------------------------
// getDefaultConfigDir
// ---------------------------------------------------------------------------

describe('getDefaultConfigDir', () => {
  let savedEnv: string | undefined

  beforeEach(() => {
    savedEnv = process.env.VAULTKEEPER_CONFIG_DIR
    delete process.env.VAULTKEEPER_CONFIG_DIR
  })

  afterEach(() => {
    if (savedEnv === undefined) {
      delete process.env.VAULTKEEPER_CONFIG_DIR
    } else {
      process.env.VAULTKEEPER_CONFIG_DIR = savedEnv
    }
  })

  it('should return a string', () => {
    expect(typeof getDefaultConfigDir()).toBe('string')
  })

  it('should include vaultkeeper in the path', () => {
    expect(getDefaultConfigDir()).toContain('vaultkeeper')
  })

  it('should return VAULTKEEPER_CONFIG_DIR when set', () => {
    process.env.VAULTKEEPER_CONFIG_DIR = '/tmp/test-vaultkeeper'
    expect(getDefaultConfigDir()).toBe('/tmp/test-vaultkeeper')
  })

  it('should ignore empty VAULTKEEPER_CONFIG_DIR', () => {
    process.env.VAULTKEEPER_CONFIG_DIR = ''
    const result = getDefaultConfigDir()
    expect(result).toContain('vaultkeeper')
    expect(result).not.toBe('')
  })

  it('should delegate to the platform default when no env override is set', () => {
    delete process.env.VAULTKEEPER_CONFIG_DIR
    expect(getDefaultConfigDir()).toBe(getPlatformDefaultConfigDir())
  })
})

// ---------------------------------------------------------------------------
// getPlatformDefaultConfigDir (issue #149)
// ---------------------------------------------------------------------------

describe('getPlatformDefaultConfigDir', () => {
  let savedEnv: string | undefined

  beforeEach(() => {
    savedEnv = process.env.VAULTKEEPER_CONFIG_DIR
  })

  afterEach(() => {
    if (savedEnv === undefined) {
      delete process.env.VAULTKEEPER_CONFIG_DIR
    } else {
      process.env.VAULTKEEPER_CONFIG_DIR = savedEnv
    }
  })

  it('should include vaultkeeper in the path', () => {
    expect(getPlatformDefaultConfigDir()).toContain('vaultkeeper')
  })

  // The whole point of this helper (vs getDefaultConfigDir): it is the
  // machine default, so a remediation hint can tell whether an active dir
  // that came from the env var differs from what a fresh shell would use.
  it('should IGNORE VAULTKEEPER_CONFIG_DIR (env-independent)', () => {
    process.env.VAULTKEEPER_CONFIG_DIR = '/tmp/env-override-vaultkeeper'
    expect(getPlatformDefaultConfigDir()).not.toBe('/tmp/env-override-vaultkeeper')
    expect(getPlatformDefaultConfigDir()).toContain('vaultkeeper')
  })
})

// ---------------------------------------------------------------------------
// loadConfig
// ---------------------------------------------------------------------------

describe('loadConfig', () => {
  afterEach(() => {
    vi.mocked(readFile).mockReset()
  })

  it('should return default config when file does not exist (ENOENT)', async () => {
    vi.mocked(readFile).mockRejectedValue(fsError('ENOENT', 'no such file or directory'))
    const config = await loadConfig('/nonexistent')
    expect(config.version).toBe(1)
    expect(config.backends).toHaveLength(1)
  })

  it('should parse a valid config file', async () => {
    vi.mocked(readFile).mockResolvedValue(JSON.stringify(validConfigJson()))
    const config = await loadConfig('/fake')
    expect(config.version).toBe(1)
    expect(config.defaults.ttlMinutes).toBe(60)
  })

  it('should throw on invalid JSON', async () => {
    vi.mocked(readFile).mockResolvedValue('not-json{{{')
    await expect(loadConfig('/fake')).rejects.toThrow('Failed to parse config file')
  })

  it('should throw a ConfigParseError with the file path, a parse location, and a remediation hint on invalid JSON (issue #68)', async () => {
    vi.mocked(readFile).mockResolvedValue('{ bad json')
    try {
      await loadConfig('/fake')
      expect.unreachable('loadConfig should have thrown')
    } catch (err) {
      if (!(err instanceof ConfigParseError)) {
        throw err
      }
      expect(err.path).toBe('/fake/config.json')
      expect(err.location).toMatch(/line \d+, column \d+/)
      expect(err.message).toContain('/fake/config.json')
      const location = err.location
      if (location === undefined) {
        expect.unreachable('location should be defined')
      }
      expect(err.message).toContain(location)
      expect(err.message).toContain('vaultkeeper config init')
    }
  })

  it('should throw on invalid config structure', async () => {
    vi.mocked(readFile).mockResolvedValue(JSON.stringify({ version: 99 }))
    await expect(loadConfig('/fake')).rejects.toThrow('version must be 1')
  })

  it('should throw a ConfigValidationError with the file path and a remediation hint on invalid config structure (issue #68)', async () => {
    vi.mocked(readFile).mockResolvedValue(JSON.stringify({ version: 99 }))
    try {
      await loadConfig('/fake')
      expect.unreachable('loadConfig should have thrown')
    } catch (err) {
      if (!(err instanceof ConfigValidationError)) {
        throw err
      }
      expect(err.message).toContain('/fake/config.json')
      expect(err.message).toContain('vaultkeeper config init')
      expect(err.field).toBe('version')
    }
  })

  // Regression: issue #118 — loadConfig previously joined the inner
  // validation diagnosis and the remediation hint with only a space
  // ("...version must be 1 Fix the file..."), reading as a run-on with no
  // sentence break. A period must now separate diagnosis from remediation.
  it('should separate the validation diagnosis from the remediation hint with a period, not a run-on (issue #118)', async () => {
    vi.mocked(readFile).mockResolvedValue(JSON.stringify({ version: 99 }))
    try {
      await loadConfig('/fake')
      expect.unreachable('loadConfig should have thrown')
    } catch (err) {
      if (!(err instanceof ConfigValidationError)) {
        throw err
      }
      expect(err.message).toContain('Config version must be 1. Fix the file')
      expect(err.message).not.toContain('Config version must be 1 Fix the file')
    }
  })

  // Issue #98: a missing config must resolve to the safe zero-config default
  // (the `file` backend), never the OS-native store — copy-pasting the first
  // documented example can never silently write to the real keychain.
  it('should resolve the safe file backend when no config file exists', async () => {
    vi.mocked(readFile).mockRejectedValue(fsError('ENOENT', 'no such file or directory'))
    const config = await loadConfig('/nonexistent')
    const firstBackend = config.backends[0]
    expect(firstBackend?.type).toBe('file')
    expect(firstBackend?.type).toBe(defaultBackendType())
    // Regardless of platform, the default is never the native credential store
    // on macOS/Windows (issue #98).
    if (platformNativeBackendType() !== 'file') {
      expect(firstBackend?.type).not.toBe(platformNativeBackendType())
    }
  })

  // Regression test for issue #68's loadConfig hardening (folded in from #92's
  // review): before this fix, loadConfig fell back to defaultConfig() on ANY
  // read error, not just ENOENT — so a genuinely broken/unreadable config
  // (e.g. a permissions error) silently returned defaults instead of
  // surfacing the problem.
  it('should rethrow a non-ENOENT read error as a typed FilesystemError instead of silently defaulting (regression: issue #68 / #92 review)', async () => {
    const cause = fsError('EACCES', 'permission denied')
    vi.mocked(readFile).mockRejectedValue(cause)
    try {
      await loadConfig('/fake')
      expect.unreachable('loadConfig should have thrown, not silently defaulted')
    } catch (err) {
      if (!(err instanceof FilesystemError)) {
        throw err
      }
      expect(err.path).toBe('/fake/config.json')
      expect(err.permission).toBe('read')
      expect(err.message).toContain('/fake/config.json')
      expect(err.message).toContain('vaultkeeper config init')
      // Regression: issue #133 — the errno code and original error must
      // survive the wrap as machine-readable `code`/`cause`, not just as
      // text embedded in the message.
      expect(err.code).toBe('EACCES')
      expect(err.cause).toBe(cause)
    }
  })

  // Regression: issue #133 — a non-permission errno (EISDIR) must also
  // survive wrapping, proving `code`/`cause` propagation isn't specific to
  // permission failures like EACCES/EPERM.
  it('should rethrow an EISDIR read error as a typed FilesystemError instead of silently defaulting', async () => {
    const cause = fsError('EISDIR', 'illegal operation on a directory')
    vi.mocked(readFile).mockRejectedValue(cause)
    try {
      await loadConfig('/fake')
      expect.unreachable('loadConfig should have thrown, not silently defaulted')
    } catch (err) {
      if (!(err instanceof FilesystemError)) {
        throw err
      }
      expect(err.code).toBe('EISDIR')
      expect(err.cause).toBe(cause)
    }
  })
})

// ---------------------------------------------------------------------------
// Plain-Error audit (issue #115)
// ---------------------------------------------------------------------------

// Regression: issue #115 audit — config.ts (all config loading and
// validation lives in this single file; there is no separate loader module)
// must throw only typed VaultError subclasses (ConfigValidationError,
// ConfigParseError, FilesystemError), never a plain `Error`. This greps the
// source directly so a future edit that reintroduces `throw new Error(...)`
// fails CI instead of silently regressing the "never throw plain Error"
// convention (see CLAUDE.md).
describe('plain-Error audit', () => {
  it('should contain no plain-Error throw (new/no-new/globalThis) in config.ts', () => {
    const configSourcePath = fileURLToPath(new URL('../../src/config.ts', import.meta.url))
    const source = readFileSync(configSourcePath, 'utf8')
    // Whitespace-tolerant and constructor-form-tolerant: a plain Error can be
    // thrown as `throw new Error(...)`, `throw Error(...)` (no `new`), or
    // `throw new globalThis.Error(...)`. Extra spaces or a line break between
    // tokens would also slip past a naive literal match. Catch all of them so
    // the "never throw plain Error" guard can't be bypassed.
    expect(source).not.toMatch(/throw\s+(?:new\s+)?(?:globalThis\.)?Error\s*\(/)
  })
})

// ---------------------------------------------------------------------------
// defaultBackendType
// ---------------------------------------------------------------------------

describe('defaultBackendType', () => {
  it('should always be the file backend, on every platform (issue #98)', () => {
    // The zero-config default is platform-independent: `file` everywhere, so a
    // missing config never silently targets the OS-native credential store.
    expect(defaultBackendType()).toBe('file')
  })
})

// ---------------------------------------------------------------------------
// platformNativeBackendType
// ---------------------------------------------------------------------------

describe('platformNativeBackendType', () => {
  it('should map the current platform to its native credential store', () => {
    // Resolution contract (see platformNativeBackendType docs): macOS ->
    // keychain, Windows -> dpapi, Linux -> secret-tool (a real shipped
    // Secret Service backend), any other platform -> file.
    const expected =
      process.platform === 'darwin'
        ? 'keychain'
        : process.platform === 'win32'
          ? 'dpapi'
          : process.platform === 'linux'
            ? 'secret-tool'
            : 'file'
    expect(platformNativeBackendType()).toBe(expected)
  })
})
