import { describe, it, expect, vi, beforeEach } from 'vitest'
import { runDoctor } from '../../../src/doctor/runner.js'

vi.mock('../../../src/doctor/checks.js', () => ({
  checkOpenssl: vi.fn(),
  checkBash: vi.fn(),
  checkPowershell: vi.fn(),
  checkSecurity: vi.fn(),
  checkSecretTool: vi.fn(),
  checkOp: vi.fn(),
  checkYkman: vi.fn(),
}))

import {
  checkOpenssl,
  checkBash,
  checkPowershell,
  checkSecurity,
  checkSecretTool,
  checkOp,
  checkYkman,
} from '../../../src/doctor/checks.js'

const mockCheckOpenssl = vi.mocked(checkOpenssl)
const mockCheckBash = vi.mocked(checkBash)
const mockCheckPowershell = vi.mocked(checkPowershell)
const mockCheckSecurity = vi.mocked(checkSecurity)
const mockCheckSecretTool = vi.mocked(checkSecretTool)
const mockCheckOp = vi.mocked(checkOp)
const mockCheckYkman = vi.mocked(checkYkman)

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
