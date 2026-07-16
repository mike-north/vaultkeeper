import { describe, it, expect, vi, beforeEach } from 'vitest'
import { runDoctor } from '../../../src/doctor/runner.js'

vi.mock('../../../src/util/platform.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/util/platform.js')>()
  return { ...actual, currentPlatform: vi.fn(actual.currentPlatform) }
})

vi.mock('../../../src/doctor/checks.js', () => ({
  checkOpenssl: vi.fn(),
  checkBash: vi.fn(),
  checkPowershell: vi.fn(),
  checkSecurity: vi.fn(),
  checkSecretTool: vi.fn(),
  checkOp: vi.fn(),
  checkYkman: vi.fn(),
}))

vi.mock('../../../src/config.js', () => ({
  loadConfig: vi.fn(),
}))

import { loadConfig } from '../../../src/config.js'
import { ConfigParseError, ConfigValidationError, FilesystemError } from '../../../src/errors.js'
import {
  checkOpenssl,
  checkBash,
  checkPowershell,
  checkSecurity,
  checkSecretTool,
  checkOp,
  checkYkman,
} from '../../../src/doctor/checks.js'
import { currentPlatform } from '../../../src/util/platform.js'

const mockCheckOpenssl = vi.mocked(checkOpenssl)
const mockCheckBash = vi.mocked(checkBash)
const mockCheckPowershell = vi.mocked(checkPowershell)
const mockCheckSecurity = vi.mocked(checkSecurity)
const mockCheckSecretTool = vi.mocked(checkSecretTool)
const mockCheckOp = vi.mocked(checkOp)
const mockCheckYkman = vi.mocked(checkYkman)
const mockCurrentPlatform = vi.mocked(currentPlatform)
const mockLoadConfig = vi.mocked(loadConfig)

beforeEach(() => {
  vi.resetAllMocks()
})

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function mockOk(name: string, version?: string) {
  return Promise.resolve(
    version !== undefined
      ? { name, status: 'ok' as const, version }
      : { name, status: 'ok' as const },
  )
}

function mockMissing(name: string, reason?: string) {
  return Promise.resolve(
    reason !== undefined
      ? { name, status: 'missing' as const, reason }
      : { name, status: 'missing' as const },
  )
}

function mockVersionUnsupported(name: string, reason?: string) {
  return Promise.resolve(
    reason !== undefined
      ? { name, status: 'version-unsupported' as const, reason }
      : { name, status: 'version-unsupported' as const },
  )
}

// ---------------------------------------------------------------------------
// macOS (darwin) platform tests
// ---------------------------------------------------------------------------

describe('runDoctor on darwin', () => {
  it('returns ready=true when all required checks pass', async () => {
    mockCheckOpenssl.mockReturnValue(mockOk('openssl', '3.0.2'))
    mockCheckSecurity.mockReturnValue(mockOk('security'))
    mockCheckOp.mockReturnValue(mockOk('op', '2.24.0'))
    mockCheckYkman.mockReturnValue(mockOk('ykman', '5.2.1'))
    mockCheckBash.mockReturnValue(mockOk('bash', 'GNU bash, version 5.2'))

    const result = await runDoctor({ platform: 'darwin' })

    expect(result.ready).toBe(true)
    expect(result.warnings).toHaveLength(0)
    expect(result.nextSteps).toHaveLength(0)
    expect(result.checks).toHaveLength(5) // openssl, security, bash, op, ykman
  })

  it('returns ready=false when openssl is missing (required)', async () => {
    mockCheckOpenssl.mockReturnValue(mockMissing('openssl', 'not found'))
    mockCheckSecurity.mockReturnValue(mockOk('security'))
    mockCheckOp.mockReturnValue(mockOk('op'))
    mockCheckYkman.mockReturnValue(mockOk('ykman'))
    mockCheckBash.mockReturnValue(mockOk('bash'))

    const result = await runDoctor({ platform: 'darwin' })

    expect(result.ready).toBe(false)
    expect(result.nextSteps.length).toBeGreaterThan(0)
    expect(result.nextSteps[0]).toContain('openssl')
  })

  it('returns ready=false when security is missing (required on darwin)', async () => {
    mockCheckOpenssl.mockReturnValue(mockOk('openssl'))
    mockCheckSecurity.mockReturnValue(mockMissing('security', 'not found'))
    mockCheckOp.mockReturnValue(mockOk('op'))
    mockCheckYkman.mockReturnValue(mockOk('ykman'))
    mockCheckBash.mockReturnValue(mockOk('bash'))

    const result = await runDoctor({ platform: 'darwin' })

    expect(result.ready).toBe(false)
    expect(result.nextSteps.some((s) => s.includes('security'))).toBe(true)
  })

  it('returns ready=true when optional op is missing (only warning)', async () => {
    mockCheckOpenssl.mockReturnValue(mockOk('openssl'))
    mockCheckSecurity.mockReturnValue(mockOk('security'))
    mockCheckOp.mockReturnValue(mockMissing('op', 'not found'))
    mockCheckYkman.mockReturnValue(mockOk('ykman'))
    mockCheckBash.mockReturnValue(mockOk('bash'))

    const result = await runDoctor({ platform: 'darwin' })

    expect(result.ready).toBe(true)
    expect(result.warnings.some((w) => w.includes('op'))).toBe(true)
    expect(result.nextSteps).toHaveLength(0)
  })

  it('returns ready=true when optional ykman is missing (only warning)', async () => {
    mockCheckOpenssl.mockReturnValue(mockOk('openssl'))
    mockCheckSecurity.mockReturnValue(mockOk('security'))
    mockCheckOp.mockReturnValue(mockOk('op'))
    mockCheckYkman.mockReturnValue(mockMissing('ykman', 'not found'))
    mockCheckBash.mockReturnValue(mockOk('bash'))

    const result = await runDoctor({ platform: 'darwin' })

    expect(result.ready).toBe(true)
    expect(result.warnings.some((w) => w.includes('ykman'))).toBe(true)
  })

  it('includes upgrade nextStep when required dep is version-unsupported', async () => {
    mockCheckOpenssl.mockReturnValue(mockVersionUnsupported('openssl', 'needs >= 1.1.1'))
    mockCheckSecurity.mockReturnValue(mockOk('security'))
    mockCheckOp.mockReturnValue(mockOk('op'))
    mockCheckYkman.mockReturnValue(mockOk('ykman'))
    mockCheckBash.mockReturnValue(mockOk('bash'))

    const result = await runDoctor({ platform: 'darwin' })

    expect(result.ready).toBe(false)
    expect(result.nextSteps.some((s) => s.includes('Upgrade'))).toBe(true)
  })

  it('includes warning (not nextStep) when optional dep is version-unsupported', async () => {
    mockCheckOpenssl.mockReturnValue(mockOk('openssl'))
    mockCheckSecurity.mockReturnValue(mockOk('security'))
    mockCheckOp.mockReturnValue(mockVersionUnsupported('op', 'too old'))
    mockCheckYkman.mockReturnValue(mockOk('ykman'))
    mockCheckBash.mockReturnValue(mockOk('bash'))

    const result = await runDoctor({ platform: 'darwin' })

    expect(result.ready).toBe(true)
    expect(result.warnings.some((w) => w.includes('op'))).toBe(true)
    expect(result.nextSteps).toHaveLength(0)
  })

  it('does not call checkPowershell or checkSecretTool on darwin', async () => {
    mockCheckOpenssl.mockReturnValue(mockOk('openssl'))
    mockCheckSecurity.mockReturnValue(mockOk('security'))
    mockCheckOp.mockReturnValue(mockOk('op'))
    mockCheckYkman.mockReturnValue(mockOk('ykman'))
    mockCheckBash.mockReturnValue(mockOk('bash'))

    await runDoctor({ platform: 'darwin' })

    expect(mockCheckPowershell).not.toHaveBeenCalled()
    expect(mockCheckSecretTool).not.toHaveBeenCalled()
  })
})

// ---------------------------------------------------------------------------
// Windows (win32) platform tests
// ---------------------------------------------------------------------------

describe('runDoctor on win32', () => {
  it('returns ready=true when openssl and powershell pass', async () => {
    mockCheckOpenssl.mockReturnValue(mockOk('openssl'))
    mockCheckPowershell.mockReturnValue(mockOk('powershell', '7.3.1'))
    mockCheckOp.mockReturnValue(mockOk('op'))
    mockCheckYkman.mockReturnValue(mockOk('ykman'))

    const result = await runDoctor({ platform: 'win32' })

    expect(result.ready).toBe(true)
  })

  it('returns ready=false when powershell is missing (required on win32)', async () => {
    mockCheckOpenssl.mockReturnValue(mockOk('openssl'))
    mockCheckPowershell.mockReturnValue(mockMissing('powershell'))
    mockCheckOp.mockReturnValue(mockOk('op'))
    mockCheckYkman.mockReturnValue(mockOk('ykman'))

    const result = await runDoctor({ platform: 'win32' })

    expect(result.ready).toBe(false)
    expect(result.nextSteps.some((s) => s.includes('powershell'))).toBe(true)
  })

  it('does not call checkSecurity, checkBash, or checkSecretTool on win32', async () => {
    mockCheckOpenssl.mockReturnValue(mockOk('openssl'))
    mockCheckPowershell.mockReturnValue(mockOk('powershell'))
    mockCheckOp.mockReturnValue(mockOk('op'))
    mockCheckYkman.mockReturnValue(mockOk('ykman'))

    await runDoctor({ platform: 'win32' })

    expect(mockCheckSecurity).not.toHaveBeenCalled()
    expect(mockCheckBash).not.toHaveBeenCalled()
    expect(mockCheckSecretTool).not.toHaveBeenCalled()
  })
})

// ---------------------------------------------------------------------------
// Linux platform tests
// ---------------------------------------------------------------------------

describe('runDoctor on linux', () => {
  it('returns ready=true when all required linux checks pass', async () => {
    mockCheckOpenssl.mockReturnValue(mockOk('openssl'))
    mockCheckBash.mockReturnValue(mockOk('bash'))
    mockCheckSecretTool.mockReturnValue(mockOk('secret-tool', '0.18.3'))
    mockCheckOp.mockReturnValue(mockOk('op'))
    mockCheckYkman.mockReturnValue(mockOk('ykman'))

    const result = await runDoctor({ platform: 'linux' })

    expect(result.ready).toBe(true)
    expect(result.checks).toHaveLength(5) // openssl, bash, secret-tool, op, ykman
  })

  it('returns ready=false when secret-tool is missing (required on linux)', async () => {
    mockCheckOpenssl.mockReturnValue(mockOk('openssl'))
    mockCheckBash.mockReturnValue(mockOk('bash'))
    mockCheckSecretTool.mockReturnValue(mockMissing('secret-tool', 'not found'))
    mockCheckOp.mockReturnValue(mockOk('op'))
    mockCheckYkman.mockReturnValue(mockOk('ykman'))

    const result = await runDoctor({ platform: 'linux' })

    expect(result.ready).toBe(false)
    expect(result.nextSteps.some((s) => s.includes('secret-tool'))).toBe(true)
  })

  it('returns ready=false when bash is missing (required on linux)', async () => {
    mockCheckOpenssl.mockReturnValue(mockOk('openssl'))
    mockCheckBash.mockReturnValue(mockMissing('bash', 'not found'))
    mockCheckSecretTool.mockReturnValue(mockOk('secret-tool'))
    mockCheckOp.mockReturnValue(mockOk('op'))
    mockCheckYkman.mockReturnValue(mockOk('ykman'))

    const result = await runDoctor({ platform: 'linux' })

    expect(result.ready).toBe(false)
  })

  it('does not call checkSecurity or checkPowershell on linux', async () => {
    mockCheckOpenssl.mockReturnValue(mockOk('openssl'))
    mockCheckBash.mockReturnValue(mockOk('bash'))
    mockCheckSecretTool.mockReturnValue(mockOk('secret-tool'))
    mockCheckOp.mockReturnValue(mockOk('op'))
    mockCheckYkman.mockReturnValue(mockOk('ykman'))

    await runDoctor({ platform: 'linux' })

    expect(mockCheckSecurity).not.toHaveBeenCalled()
    expect(mockCheckPowershell).not.toHaveBeenCalled()
  })
})

// ---------------------------------------------------------------------------
// Result shape tests
// ---------------------------------------------------------------------------

describe('runDoctor result shape', () => {
  it('checks array contains all run checks', async () => {
    mockCheckOpenssl.mockReturnValue(mockOk('openssl'))
    mockCheckSecurity.mockReturnValue(mockOk('security'))
    mockCheckOp.mockReturnValue(mockOk('op'))
    mockCheckYkman.mockReturnValue(mockOk('ykman'))
    mockCheckBash.mockReturnValue(mockOk('bash'))

    const result = await runDoctor({ platform: 'darwin' })

    const names = result.checks.map((c) => c.name)
    expect(names).toContain('openssl')
    expect(names).toContain('security')
    expect(names).toContain('op')
    expect(names).toContain('ykman')
  })

  it('collects multiple warnings when multiple optional deps are missing', async () => {
    mockCheckOpenssl.mockReturnValue(mockOk('openssl'))
    mockCheckSecurity.mockReturnValue(mockOk('security'))
    mockCheckOp.mockReturnValue(mockMissing('op', 'not found'))
    mockCheckYkman.mockReturnValue(mockMissing('ykman', 'not found'))
    mockCheckBash.mockReturnValue(mockOk('bash'))

    const result = await runDoctor({ platform: 'darwin' })

    expect(result.ready).toBe(true)
    expect(result.warnings).toHaveLength(2)
  })

  it('collects multiple nextSteps when multiple required deps are missing', async () => {
    mockCheckOpenssl.mockReturnValue(mockMissing('openssl'))
    mockCheckSecurity.mockReturnValue(mockMissing('security'))
    mockCheckOp.mockReturnValue(mockOk('op'))
    mockCheckYkman.mockReturnValue(mockOk('ykman'))
    mockCheckBash.mockReturnValue(mockOk('bash'))

    const result = await runDoctor({ platform: 'darwin' })

    expect(result.ready).toBe(false)
    expect(result.nextSteps).toHaveLength(2)
  })
})

// ---------------------------------------------------------------------------
// Unsupported platform — regression test for graceful degradation
// Before this fix, currentPlatform() threw a raw Error; now runDoctor()
// catches it and returns a non-ready PreflightResult instead.
// ---------------------------------------------------------------------------

describe('runDoctor on unsupported platform', () => {
  it('returns ready=false with a nextStep when currentPlatform throws', async () => {
    mockCurrentPlatform.mockImplementation(() => {
      throw new Error('Unsupported platform: freebsd')
    })

    const result = await runDoctor()

    expect(result.ready).toBe(false)
    expect(result.checks).toHaveLength(0)
    expect(result.warnings).toHaveLength(0)
    expect(result.nextSteps).toHaveLength(1)
    expect(result.nextSteps[0]).toContain('Unsupported platform')
  })

  it('does not invoke any check functions when currentPlatform throws', async () => {
    mockCurrentPlatform.mockImplementation(() => {
      throw new Error('Unsupported platform: freebsd')
    })

    await runDoctor()

    expect(mockCheckOpenssl).not.toHaveBeenCalled()
    expect(mockCheckBash).not.toHaveBeenCalled()
    expect(mockCheckSecurity).not.toHaveBeenCalled()
    expect(mockCheckPowershell).not.toHaveBeenCalled()
    expect(mockCheckSecretTool).not.toHaveBeenCalled()
    expect(mockCheckOp).not.toHaveBeenCalled()
    expect(mockCheckYkman).not.toHaveBeenCalled()
  })
})

// ---------------------------------------------------------------------------
// Backend-aware doctor checks — when backends are provided, only the
// system dependencies needed by enabled backends should be required.
// ---------------------------------------------------------------------------

describe('backend-aware checks on linux', () => {
  it('demotes secret-tool from required to optional when only file backend is enabled', async () => {
    mockCheckOpenssl.mockReturnValue(mockOk('openssl'))
    mockCheckBash.mockReturnValue(mockOk('bash'))
    mockCheckSecretTool.mockReturnValue(mockMissing('secret-tool', 'not found'))
    mockCheckOp.mockReturnValue(mockMissing('op'))
    mockCheckYkman.mockReturnValue(mockMissing('ykman'))

    const result = await runDoctor({
      platform: 'linux',
      backends: [{ type: 'file', enabled: true }],
    })

    // secret-tool is missing but file backend does not need it → ready
    expect(result.ready).toBe(true)
    // secret-tool should appear as a warning, not a nextStep
    expect(result.warnings.some((w) => w.includes('secret-tool'))).toBe(true)
    expect(result.nextSteps).toHaveLength(0)
  })

  it('keeps secret-tool required when secret-tool backend is enabled', async () => {
    mockCheckOpenssl.mockReturnValue(mockOk('openssl'))
    mockCheckBash.mockReturnValue(mockOk('bash'))
    mockCheckSecretTool.mockReturnValue(mockMissing('secret-tool', 'not found'))
    mockCheckOp.mockReturnValue(mockMissing('op'))
    mockCheckYkman.mockReturnValue(mockMissing('ykman'))

    const result = await runDoctor({
      platform: 'linux',
      backends: [{ type: 'secret-tool', enabled: true }],
    })

    expect(result.ready).toBe(false)
    expect(result.nextSteps.some((s) => s.includes('secret-tool'))).toBe(true)
  })

  it('falls back to platform defaults when no backends option is provided', async () => {
    mockCheckOpenssl.mockReturnValue(mockOk('openssl'))
    mockCheckBash.mockReturnValue(mockOk('bash'))
    mockCheckSecretTool.mockReturnValue(mockMissing('secret-tool', 'not found'))
    mockCheckOp.mockReturnValue(mockMissing('op'))
    mockCheckYkman.mockReturnValue(mockMissing('ykman'))

    const result = await runDoctor({ platform: 'linux' })

    // Without backends option, secret-tool is required on linux (backward compat)
    expect(result.ready).toBe(false)
    expect(result.nextSteps.some((s) => s.includes('secret-tool'))).toBe(true)
  })

  it('promotes op to required when 1password backend is enabled', async () => {
    mockCheckOpenssl.mockReturnValue(mockOk('openssl'))
    mockCheckBash.mockReturnValue(mockOk('bash'))
    mockCheckSecretTool.mockReturnValue(mockOk('secret-tool'))
    mockCheckOp.mockReturnValue(mockMissing('op', 'not found'))
    mockCheckYkman.mockReturnValue(mockOk('ykman'))

    const result = await runDoctor({
      platform: 'linux',
      backends: [
        { type: 'file', enabled: true },
        { type: '1password', enabled: true, plugin: true },
      ],
    })

    expect(result.ready).toBe(false)
    expect(result.nextSteps.some((s) => s.includes('op'))).toBe(true)
  })

  it('promotes ykman to required when yubikey backend is enabled', async () => {
    mockCheckOpenssl.mockReturnValue(mockOk('openssl'))
    mockCheckBash.mockReturnValue(mockOk('bash'))
    mockCheckSecretTool.mockReturnValue(mockOk('secret-tool'))
    mockCheckOp.mockReturnValue(mockOk('op'))
    mockCheckYkman.mockReturnValue(mockMissing('ykman', 'not found'))

    const result = await runDoctor({
      platform: 'linux',
      backends: [
        { type: 'file', enabled: true },
        { type: 'yubikey', enabled: true, plugin: true },
      ],
    })

    expect(result.ready).toBe(false)
    expect(result.nextSteps.some((s) => s.includes('ykman'))).toBe(true)
  })

  it('demotes all platform checks when backends is an empty array', async () => {
    mockCheckOpenssl.mockReturnValue(mockOk('openssl'))
    mockCheckBash.mockReturnValue(mockOk('bash'))
    mockCheckSecretTool.mockReturnValue(mockMissing('secret-tool', 'not found'))
    mockCheckOp.mockReturnValue(mockMissing('op'))
    mockCheckYkman.mockReturnValue(mockMissing('ykman'))

    const result = await runDoctor({
      platform: 'linux',
      backends: [],
    })

    // Empty backends = no backend needs secret-tool → demoted to optional
    expect(result.ready).toBe(true)
    expect(result.warnings.some((w) => w.includes('secret-tool'))).toBe(true)
  })
})

describe('backend-aware checks on darwin', () => {
  it('demotes security from required to optional when only file backend is enabled', async () => {
    mockCheckOpenssl.mockReturnValue(mockOk('openssl'))
    mockCheckSecurity.mockReturnValue(mockMissing('security', 'not found'))
    mockCheckBash.mockReturnValue(mockOk('bash'))
    mockCheckOp.mockReturnValue(mockMissing('op'))
    mockCheckYkman.mockReturnValue(mockMissing('ykman'))

    const result = await runDoctor({
      platform: 'darwin',
      backends: [{ type: 'file', enabled: true }],
    })

    expect(result.ready).toBe(true)
    expect(result.warnings.some((w) => w.includes('security'))).toBe(true)
    expect(result.nextSteps).toHaveLength(0)
  })

  it('keeps security required when keychain backend is enabled', async () => {
    mockCheckOpenssl.mockReturnValue(mockOk('openssl'))
    mockCheckSecurity.mockReturnValue(mockMissing('security', 'not found'))
    mockCheckBash.mockReturnValue(mockOk('bash'))
    mockCheckOp.mockReturnValue(mockMissing('op'))
    mockCheckYkman.mockReturnValue(mockMissing('ykman'))

    const result = await runDoctor({
      platform: 'darwin',
      backends: [{ type: 'keychain', enabled: true }],
    })

    expect(result.ready).toBe(false)
    expect(result.nextSteps.some((s) => s.includes('security'))).toBe(true)
  })
})

describe('backend-aware checks on win32', () => {
  it('demotes powershell from required to optional when only file backend is enabled', async () => {
    mockCheckOpenssl.mockReturnValue(mockOk('openssl'))
    mockCheckPowershell.mockReturnValue(mockMissing('powershell', 'not found'))
    mockCheckOp.mockReturnValue(mockMissing('op'))
    mockCheckYkman.mockReturnValue(mockMissing('ykman'))

    const result = await runDoctor({
      platform: 'win32',
      backends: [{ type: 'file', enabled: true }],
    })

    expect(result.ready).toBe(true)
    expect(result.warnings.some((w) => w.includes('powershell'))).toBe(true)
    expect(result.nextSteps).toHaveLength(0)
  })

  it('keeps powershell required when dpapi backend is enabled', async () => {
    mockCheckOpenssl.mockReturnValue(mockOk('openssl'))
    mockCheckPowershell.mockReturnValue(mockMissing('powershell', 'not found'))
    mockCheckOp.mockReturnValue(mockMissing('op'))
    mockCheckYkman.mockReturnValue(mockMissing('ykman'))

    const result = await runDoctor({
      platform: 'win32',
      backends: [{ type: 'dpapi', enabled: true }],
    })

    expect(result.ready).toBe(false)
    expect(result.nextSteps.some((s) => s.includes('powershell'))).toBe(true)
  })
})

describe('backend-aware checks ignore disabled backends', () => {
  it('does not require secret-tool when secret-tool backend is present but disabled', async () => {
    mockCheckOpenssl.mockReturnValue(mockOk('openssl'))
    mockCheckBash.mockReturnValue(mockOk('bash'))
    mockCheckSecretTool.mockReturnValue(mockMissing('secret-tool', 'not found'))
    mockCheckOp.mockReturnValue(mockMissing('op'))
    mockCheckYkman.mockReturnValue(mockMissing('ykman'))

    const result = await runDoctor({
      platform: 'linux',
      backends: [
        { type: 'file', enabled: true },
        { type: 'secret-tool', enabled: false },
      ],
    })

    expect(result.ready).toBe(true)
    expect(result.warnings.some((w) => w.includes('secret-tool'))).toBe(true)
  })

  it('does not require security when keychain backend is present but disabled on darwin', async () => {
    mockCheckOpenssl.mockReturnValue(mockOk('openssl'))
    mockCheckSecurity.mockReturnValue(mockMissing('security', 'not found'))
    mockCheckBash.mockReturnValue(mockOk('bash'))
    mockCheckOp.mockReturnValue(mockMissing('op'))
    mockCheckYkman.mockReturnValue(mockMissing('ykman'))

    const result = await runDoctor({
      platform: 'darwin',
      backends: [
        { type: 'file', enabled: true },
        { type: 'keychain', enabled: false },
      ],
    })

    expect(result.ready).toBe(true)
    expect(result.warnings.some((w) => w.includes('security'))).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// configDir option — doctor loads and validates the config itself, adding a
// "config" check. An invalid config is a failing, required check (issue #68).
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// checks[].required — each check result is scoped by whether it is required
// for the active/configured backend(s), so the CLI can visually separate
// "checks for your active backend" from "optional plugin backends (not
// configured)" instead of rendering every non-'ok' status as a failure
// (issue #116: a fresh file-default doctor run must not red-X ykman/op).
// ---------------------------------------------------------------------------

describe('checks[].required scoping (issue #116)', () => {
  it('marks op and ykman as not required when only the file backend is enabled', async () => {
    mockCheckOpenssl.mockReturnValue(mockOk('openssl'))
    mockCheckSecurity.mockReturnValue(mockOk('security'))
    mockCheckBash.mockReturnValue(mockOk('bash'))
    mockCheckOp.mockReturnValue(mockMissing('op', 'not found'))
    mockCheckYkman.mockReturnValue(mockMissing('ykman', 'not found'))

    const result = await runDoctor({
      platform: 'darwin',
      backends: [{ type: 'file', enabled: true }],
    })

    expect(result.ready).toBe(true)
    expect(result.checks.find((c) => c.name === 'op')?.required).toBe(false)
    expect(result.checks.find((c) => c.name === 'ykman')?.required).toBe(false)
  })

  it('marks security as required when the keychain backend is enabled, but op/ykman stay optional', async () => {
    mockCheckOpenssl.mockReturnValue(mockOk('openssl'))
    mockCheckSecurity.mockReturnValue(mockOk('security'))
    mockCheckBash.mockReturnValue(mockOk('bash'))
    mockCheckOp.mockReturnValue(mockMissing('op', 'not found'))
    mockCheckYkman.mockReturnValue(mockMissing('ykman', 'not found'))

    const result = await runDoctor({
      platform: 'darwin',
      backends: [{ type: 'keychain', enabled: true }],
    })

    expect(result.checks.find((c) => c.name === 'security')?.required).toBe(true)
    expect(result.checks.find((c) => c.name === 'op')?.required).toBe(false)
    expect(result.checks.find((c) => c.name === 'ykman')?.required).toBe(false)
  })

  it('marks ykman as required when the yubikey backend is enabled', async () => {
    mockCheckOpenssl.mockReturnValue(mockOk('openssl'))
    mockCheckSecurity.mockReturnValue(mockOk('security'))
    mockCheckBash.mockReturnValue(mockOk('bash'))
    mockCheckOp.mockReturnValue(mockMissing('op', 'not found'))
    mockCheckYkman.mockReturnValue(mockMissing('ykman', 'not found'))

    const result = await runDoctor({
      platform: 'darwin',
      backends: [
        { type: 'file', enabled: true },
        { type: 'yubikey', enabled: true, plugin: true },
      ],
    })

    expect(result.checks.find((c) => c.name === 'ykman')?.required).toBe(true)
    // op stays optional — only yubikey was enabled.
    expect(result.checks.find((c) => c.name === 'op')?.required).toBe(false)
  })
})

describe('runDoctor with configDir', () => {
  it('adds an ok "config" check and scopes backend checks when the config loads successfully', async () => {
    mockCheckOpenssl.mockReturnValue(mockOk('openssl'))
    mockCheckBash.mockReturnValue(mockOk('bash'))
    mockCheckSecretTool.mockReturnValue(mockMissing('secret-tool', 'not found'))
    mockCheckOp.mockReturnValue(mockMissing('op'))
    mockCheckYkman.mockReturnValue(mockMissing('ykman'))
    mockLoadConfig.mockResolvedValue({
      version: 1,
      backends: [{ type: 'file', enabled: true }],
      keyRotation: { gracePeriodDays: 7 },
      defaults: { ttlMinutes: 60, trustTier: 3 },
    })

    const result = await runDoctor({ platform: 'linux', configDir: '/fake' })

    const configCheck = result.checks.find((c) => c.name === 'config')
    expect(configCheck?.status).toBe('ok')
    expect(configCheck?.required).toBe(true)
    // file backend does not require secret-tool -> demoted to optional, ready stays true
    expect(result.ready).toBe(true)
    expect(result.checks.find((c) => c.name === 'op')?.required).toBe(false)
    expect(result.checks.find((c) => c.name === 'ykman')?.required).toBe(false)
    expect(mockLoadConfig).toHaveBeenCalledWith('/fake')
  })

  it('reports a failing required "config" check with the underlying error message when the config is invalid', async () => {
    mockCheckOpenssl.mockReturnValue(mockOk('openssl'))
    mockCheckBash.mockReturnValue(mockOk('bash'))
    mockCheckSecretTool.mockReturnValue(mockOk('secret-tool'))
    mockCheckOp.mockReturnValue(mockMissing('op'))
    mockCheckYkman.mockReturnValue(mockMissing('ykman'))
    mockLoadConfig.mockRejectedValue(
      new ConfigParseError(
        "Failed to parse config file at /fake/config.json at line 1, column 3: Unexpected token. Run 'vaultkeeper config init' to create a valid config.",
        '/fake/config.json',
        'line 1, column 3',
      ),
    )

    const result = await runDoctor({ platform: 'linux', configDir: '/fake' })

    const configCheck = result.checks.find((c) => c.name === 'config')
    expect(configCheck?.status).toBe('invalid')
    expect(configCheck?.reason).toContain('/fake/config.json')
    expect(configCheck?.reason).toContain('line 1, column 3')
    expect(result.ready).toBe(false)
    expect(result.nextSteps.some((s) => s.includes('/fake/config.json'))).toBe(true)
  })

  // Issue #130: the invalid "config" check carries structured,
  // remediation-free error context (kind + configPath + optional parse
  // location) so a CLI consumer can build its own remediation instead of
  // parsing the library's `reason` prose.
  it('attaches structured config-parse error context on a JSON parse failure', async () => {
    mockCheckOpenssl.mockReturnValue(mockOk('openssl'))
    mockCheckBash.mockReturnValue(mockOk('bash'))
    mockCheckSecretTool.mockReturnValue(mockOk('secret-tool'))
    mockCheckOp.mockReturnValue(mockMissing('op'))
    mockCheckYkman.mockReturnValue(mockMissing('ykman'))
    mockLoadConfig.mockRejectedValue(
      new ConfigParseError(
        "Failed to parse config file at /fake/config.json at line 1, column 3: Unexpected token. Run 'vaultkeeper config init' to create a valid config.",
        '/fake/config.json',
        'line 1, column 3',
      ),
    )

    const result = await runDoctor({ platform: 'linux', configDir: '/fake' })

    const configCheck = result.checks.find((c) => c.name === 'config')
    expect(configCheck?.error).toEqual({
      kind: 'config-parse',
      configPath: '/fake/config.json',
      location: 'line 1, column 3',
    })
  })

  it('attaches structured config-validation error context (no location) on a schema failure', async () => {
    mockCheckOpenssl.mockReturnValue(mockOk('openssl'))
    mockCheckBash.mockReturnValue(mockOk('bash'))
    mockCheckSecretTool.mockReturnValue(mockOk('secret-tool'))
    mockCheckOp.mockReturnValue(mockMissing('op'))
    mockCheckYkman.mockReturnValue(mockMissing('ykman'))
    mockLoadConfig.mockRejectedValue(
      new ConfigValidationError(
        'Invalid config at /fake/config.json: Config version must be 1. Fix the file — either install @vaultkeeper/cli and run ...',
        'version',
        '/fake/config.json',
      ),
    )

    const result = await runDoctor({ platform: 'linux', configDir: '/fake' })

    const configCheck = result.checks.find((c) => c.name === 'config')
    expect(configCheck?.error).toEqual({
      kind: 'config-validation',
      configPath: '/fake/config.json',
    })
    // Validation failures have no parse location.
    expect(configCheck?.error?.location).toBeUndefined()
  })

  it('falls back to the configDir-derived path when a validation error has no file path', async () => {
    mockCheckOpenssl.mockReturnValue(mockOk('openssl'))
    mockCheckBash.mockReturnValue(mockOk('bash'))
    mockCheckSecretTool.mockReturnValue(mockOk('secret-tool'))
    mockCheckOp.mockReturnValue(mockMissing('op'))
    mockCheckYkman.mockReturnValue(mockMissing('ykman'))
    mockLoadConfig.mockRejectedValue(
      new ConfigValidationError('Invalid config: Config version must be 1.', 'version'),
    )

    const result = await runDoctor({ platform: 'linux', configDir: '/fake' })

    const configCheck = result.checks.find((c) => c.name === 'config')
    expect(configCheck?.error?.configPath).toBe('/fake/config.json')
  })

  // Issue #169: a config file that cannot be READ (e.g. EACCES on the file or
  // its parent dir, chmod-000) is wrapped by `loadConfig` as a FilesystemError.
  // The runner must record it as a failing `config` check with structured
  // `config-read` context (carrying the errno `code`) so a CLI consumer can
  // render a permissions-specific remediation — not `config init --force`,
  // which cannot fix a read-permission problem.
  it('attaches structured config-read error context (with errno code) on a filesystem read failure', async () => {
    mockCheckOpenssl.mockReturnValue(mockOk('openssl'))
    mockCheckBash.mockReturnValue(mockOk('bash'))
    mockCheckSecretTool.mockReturnValue(mockOk('secret-tool'))
    mockCheckOp.mockReturnValue(mockMissing('op'))
    mockCheckYkman.mockReturnValue(mockMissing('ykman'))
    const cause = Object.assign(new Error('EACCES: permission denied'), { code: 'EACCES' })
    mockLoadConfig.mockRejectedValue(
      new FilesystemError(
        'Cannot read config file at /fake/config.json: EACCES: permission denied. ...',
        '/fake/config.json',
        'read',
        cause,
      ),
    )

    const result = await runDoctor({ platform: 'linux', configDir: '/fake' })

    const configCheck = result.checks.find((c) => c.name === 'config')
    expect(configCheck?.status).toBe('invalid')
    expect(configCheck?.required).toBe(true)
    expect(result.ready).toBe(false)
    expect(configCheck?.error).toEqual({
      kind: 'config-read',
      configPath: '/fake/config.json',
      code: 'EACCES',
    })
  })

  it('records config-read error context with an undefined code when the cause carries no errno', async () => {
    mockCheckOpenssl.mockReturnValue(mockOk('openssl'))
    mockCheckBash.mockReturnValue(mockOk('bash'))
    mockCheckSecretTool.mockReturnValue(mockOk('secret-tool'))
    mockCheckOp.mockReturnValue(mockMissing('op'))
    mockCheckYkman.mockReturnValue(mockMissing('ykman'))
    // A FilesystemError with no underlying errno cause (the pre-#141 shape).
    mockLoadConfig.mockRejectedValue(
      new FilesystemError(
        'Cannot read config file at /fake/config.json.',
        '/fake/config.json',
        'read',
      ),
    )

    const result = await runDoctor({ platform: 'linux', configDir: '/fake' })

    const configCheck = result.checks.find((c) => c.name === 'config')
    expect(configCheck?.error).toEqual({
      kind: 'config-read',
      configPath: '/fake/config.json',
      code: undefined,
    })
  })

  it('leaves `error` undefined for an unrecognized config load failure', async () => {
    mockCheckOpenssl.mockReturnValue(mockOk('openssl'))
    mockCheckBash.mockReturnValue(mockOk('bash'))
    mockCheckSecretTool.mockReturnValue(mockOk('secret-tool'))
    mockCheckOp.mockReturnValue(mockMissing('op'))
    mockCheckYkman.mockReturnValue(mockMissing('ykman'))
    mockLoadConfig.mockRejectedValue(new Error('some unexpected failure'))

    const result = await runDoctor({ platform: 'linux', configDir: '/fake' })

    const configCheck = result.checks.find((c) => c.name === 'config')
    expect(configCheck?.status).toBe('invalid')
    expect(configCheck?.error).toBeUndefined()
    // The human-readable reason is still available as a fallback.
    expect(configCheck?.reason).toContain('some unexpected failure')
  })

  it('does not load config when an explicit backends option is also provided', async () => {
    mockCheckOpenssl.mockReturnValue(mockOk('openssl'))
    mockCheckBash.mockReturnValue(mockOk('bash'))
    mockCheckSecretTool.mockReturnValue(mockOk('secret-tool'))
    mockCheckOp.mockReturnValue(mockOk('op'))
    mockCheckYkman.mockReturnValue(mockOk('ykman'))

    const result = await runDoctor({
      platform: 'linux',
      configDir: '/fake',
      backends: [{ type: 'file', enabled: true }],
    })

    expect(mockLoadConfig).not.toHaveBeenCalled()
    expect(result.checks.find((c) => c.name === 'config')).toBeUndefined()
  })
})
