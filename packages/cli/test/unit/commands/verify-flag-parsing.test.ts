/**
 * `verify` flag-parsing tests (issue #216, item 3).
 *
 * `--public-key` / `--signature` are **file-path-only** flags. Two ways a
 * caller can wrongly pass inline PEM material must produce a clear, actionable
 * usage error (exit 2) instead of node's opaque "argument is ambiguous" or a
 * confusing downstream ENOENT:
 *
 *   1. Space-separated inline PEM (`--public-key -----BEGIN…`) — node's
 *      parseArgs rejects any space-separated value starting with `-` as
 *      ambiguous.
 *   2. Equals-form inline PEM (`--public-key=-----BEGIN…`) — parses cleanly but
 *      is key material, not a path.
 *
 * These error paths return before any stdin read or vault work, so the tests
 * need neither stdin nor a backend.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'

// `verify.ts` imports `vaultkeeper`; mock it so these tests never require the
// library's build output. The flag-parsing error paths under test return before
// any `VaultKeeper.verify()` call anyway.
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

const { verifyCommand } = await import('../../../src/commands/verify.js')

describe('verify --public-key/--signature reject inline PEM with a clear usage error', () => {
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

  const INLINE_PEM = '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA\n-----END PUBLIC KEY-----'

  it('exits 2 with a file-path hint for a space-separated inline PEM (was "argument is ambiguous")', async () => {
    const code = await verifyCommand(['--public-key', INLINE_PEM, '--signature', '/tmp/sig'])
    expect(code).toBe(2)
    // The old bare node message must be replaced by an actionable one.
    expect(stderrOutput).not.toContain('argument is ambiguous')
    expect(stderrOutput).toContain('file PATH')
    expect(stderrOutput).toContain('-----BEGIN')
    // Points at the equals-form escape for a legitimately dash-leading path,
    // covering BOTH flags the message names (not just --public-key).
    expect(stderrOutput).toContain('--public-key=<path>')
    expect(stderrOutput).toContain('--signature=<path>')
  })

  it('exits 2 with a file-path hint for an equals-form inline public key', async () => {
    const code = await verifyCommand([`--public-key=${INLINE_PEM}`, '--signature', '/tmp/sig'])
    expect(code).toBe(2)
    expect(stderrOutput).toContain('--public-key takes a file PATH')
    expect(stderrOutput).not.toContain('argument is ambiguous')
  })

  it('exits 2 with a file-path hint for an equals-form inline signature', async () => {
    const code = await verifyCommand(['--public-key', '/tmp/pub.pem', `--signature=${INLINE_PEM}`])
    expect(code).toBe(2)
    expect(stderrOutput).toContain('--signature takes a file PATH')
  })

  it('still points at the file-path usage line for an unknown flag', async () => {
    const code = await verifyCommand(['--bogus', 'x'])
    expect(code).toBe(2)
    expect(stderrOutput).toContain('Usage: vaultkeeper verify --public-key <pem-path>')
  })

  it('reports both flags as required AND prints the Usage line when one is missing', async () => {
    const code = await verifyCommand(['--public-key', '/tmp/pub.pem'])
    expect(code).toBe(2)
    expect(stderrOutput).toContain('--public-key and --signature are both required')
    // The missing-flags path must be as actionable as the parse-error and
    // inline-PEM paths: it prints the Usage hint too.
    expect(stderrOutput).toContain('Usage: vaultkeeper verify --public-key <pem-path>')
  })
})
