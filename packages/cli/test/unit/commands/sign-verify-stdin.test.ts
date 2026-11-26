import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'

const configDir = '/tmp/vaultkeeper-test-config-dir'

// The commands import `vaultkeeper`; mock it so these tests never touch a real
// backend. The stdin guard fires before any vault work anyway.
vi.mock('vaultkeeper', async (importOriginal) => {
  const { mockVaultkeeperModule } = await import('../../support/mock-vaultkeeper-module.js')
  return mockVaultkeeperModule(importOriginal, {
    VaultKeeper: {
      init: vi.fn(),
      verify: vi.fn(),
    },
    defaultBackendType: vi.fn().mockReturnValue('file'),
  })
})

/**
 * Put stdin into "string mode": yield a raw string chunk instead of a Buffer.
 * readStdinBytes() enforces buffer mode, so this triggers its programming-error
 * guard — the case these tests pin.
 */
function mockStdinYieldsString(value: string): void {
  vi.spyOn(process.stdin, Symbol.asyncIterator).mockImplementation(async function* () {
    await Promise.resolve()
    yield value
  })
}

describe('sign/verify handle a readStdinBytes failure through their own error path', () => {
  let stderrOutput: string

  beforeEach(() => {
    stderrOutput = ''
    vi.spyOn(process.stderr, 'write').mockImplementation((chunk) => {
      stderrOutput += String(chunk)
      return true
    })
    vi.spyOn(process.stdout, 'write').mockImplementation(() => true)
  })

  afterEach(() => {
    vi.restoreAllMocks()
    vi.clearAllMocks()
  })

  // A stdin chunk arriving as a string means stdin was put in string mode — a
  // programming error readStdinBytes() throws on. The command must surface it as
  // a formatted exit 1, not let it escape as an unhandled rejection to the
  // top-level fatal handler.
  it('sign returns 1 (not an unhandled throw) when stdin is in string mode', async () => {
    mockStdinYieldsString('a string chunk')
    const { signCommand } = await import('../../../src/commands/sign.js')
    const code = await signCommand(['--name', 'k', '--skip-doctor'], configDir)
    expect(code).toBe(1)
    expect(stderrOutput).toContain('stdin must not be in string mode')
  })

  it('verify returns 1 (not an unhandled throw) when stdin is in string mode', async () => {
    mockStdinYieldsString('a string chunk')
    const { verifyCommand } = await import('../../../src/commands/verify.js')
    const code = await verifyCommand(['--public-key', '/tmp/pub.pem', '--signature', '/tmp/sig'])
    expect(code).toBe(1)
    expect(stderrOutput).toContain('stdin must not be in string mode')
  })
})
