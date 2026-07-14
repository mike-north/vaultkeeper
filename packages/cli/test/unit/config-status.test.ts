import { describe, it, expect, vi, afterEach } from 'vitest'

vi.mock('node:fs/promises', () => ({
  access: vi.fn(),
}))

// Must import after mock declaration
const { access } = await import('node:fs/promises')
const { configFileExists, noConfigMessage } = await import('../../src/config-status.js')

/** Build a Node.js-shaped filesystem error with a `code` (e.g. 'ENOENT'). */
function fsError(code: string, message: string): NodeJS.ErrnoException {
  return Object.assign(new Error(message), { code })
}

describe('configFileExists', () => {
  afterEach(() => {
    vi.mocked(access).mockReset()
  })

  it('returns true when config.json is accessible', async () => {
    vi.mocked(access).mockResolvedValue(undefined)
    await expect(configFileExists('/fake')).resolves.toBe(true)
  })

  it('returns false when config.json does not exist (ENOENT)', async () => {
    vi.mocked(access).mockRejectedValue(fsError('ENOENT', 'no such file or directory'))
    await expect(configFileExists('/fake')).resolves.toBe(false)
  })

  // Regression test (PR #94 review): configFileExists previously treated
  // ANY fs.access failure as "no config file", so a config that exists but
  // isn't readable (EACCES on a parent directory, EPERM, etc.) was silently
  // reported as absent — the same class of bug loadConfig's ENOENT-only
  // fallback fixes for issue #68. It must now rethrow non-ENOENT errors
  // instead of reporting "no config file".
  it('rethrows a non-ENOENT error instead of reporting "no config file" (regression: PR #94 review)', async () => {
    vi.mocked(access).mockRejectedValue(fsError('EACCES', 'permission denied'))
    await expect(configFileExists('/fake')).rejects.toMatchObject({ code: 'EACCES' })
  })

  it('rethrows an EPERM error instead of reporting "no config file"', async () => {
    vi.mocked(access).mockRejectedValue(fsError('EPERM', 'operation not permitted'))
    await expect(configFileExists('/fake')).rejects.toMatchObject({ code: 'EPERM' })
  })
})

describe('noConfigMessage', () => {
  it('names the resolved backend and points at config init', () => {
    const message = noConfigMessage('keychain')
    expect(message).toContain('keychain')
    expect(message).toContain('vaultkeeper config init')
  })
})
