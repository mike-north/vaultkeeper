import { describe, it, expect, vi, afterEach } from 'vitest'
import { validateConfig, loadConfig, getDefaultConfigDir } from '../../src/config.js'

vi.mock('node:fs/promises', () => ({
  readFile: vi.fn(),
}))

// Must import after mock declaration
const { readFile } = await import('node:fs/promises')

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

  // Negative tests
  it('should reject non-object', () => {
    expect(() => validateConfig('string')).toThrow('Config must be an object')
    expect(() => validateConfig(null)).toThrow('Config must be an object')
    expect(() => validateConfig(42)).toThrow('Config must be an object')
  })

  it('should reject wrong version', () => {
    expect(() => validateConfig({ ...validConfigJson(), version: 2 })).toThrow('version must be 1')
  })

  it('should reject empty backends', () => {
    expect(() => validateConfig({ ...validConfigJson(), backends: [] })).toThrow(
      'at least one backend',
    )
  })

  it('should reject backend with missing type', () => {
    expect(() =>
      validateConfig({ ...validConfigJson(), backends: [{ enabled: true }] }),
    ).toThrow('type must be a non-empty string')
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
  it('should return a string', () => {
    expect(typeof getDefaultConfigDir()).toBe('string')
  })

  it('should include vaultkeeper in the path', () => {
    expect(getDefaultConfigDir()).toContain('vaultkeeper')
  })
})

// ---------------------------------------------------------------------------
// loadConfig
// ---------------------------------------------------------------------------

describe('loadConfig', () => {
  afterEach(() => {
    vi.mocked(readFile).mockReset()
  })

  it('should return default config when file does not exist', async () => {
    vi.mocked(readFile).mockRejectedValue(new Error('ENOENT'))
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

  it('should throw on invalid config structure', async () => {
    vi.mocked(readFile).mockResolvedValue(JSON.stringify({ version: 99 }))
    await expect(loadConfig('/fake')).rejects.toThrow('version must be 1')
  })
})
