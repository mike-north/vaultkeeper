import { describe, it, expect, vi, afterEach } from 'vitest'

vi.mock('node:fs/promises', () => ({
  access: vi.fn(),
}))

// Must import after mock declaration
const { access } = await import('node:fs/promises')
const { configFileExists, noConfigMessage } = await import('../../src/config-status.js')
const { FilesystemError } = await import('vaultkeeper')

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
  // fallback fixes for issue #68. It must not report "no config file".
  //
  // Issue #181: it must rethrow a non-ENOENT error as a typed FilesystemError
  // on the `config.json` read path (`permission: 'read'`, `path` =
  // `configDir/config.json`, `code` = the original errno), so `formatError`
  // renders the CLI's shared unreadable-config remediation instead of leaking
  // the raw Node `EACCES: … access '.../config.json'` string.
  it('rethrows an EACCES failure as a typed FilesystemError on the config.json read path (issue #181)', async () => {
    vi.mocked(access).mockRejectedValue(fsError('EACCES', 'permission denied'))
    await expect(configFileExists('/fake')).rejects.toBeInstanceOf(FilesystemError)
    await expect(configFileExists('/fake')).rejects.toMatchObject({
      code: 'EACCES',
      permission: 'read',
      path: '/fake/config.json',
    })
  })

  it('rethrows an EPERM failure as a typed FilesystemError, preserving the errno (issue #181)', async () => {
    vi.mocked(access).mockRejectedValue(fsError('EPERM', 'operation not permitted'))
    await expect(configFileExists('/fake')).rejects.toBeInstanceOf(FilesystemError)
    await expect(configFileExists('/fake')).rejects.toMatchObject({
      code: 'EPERM',
      permission: 'read',
      path: '/fake/config.json',
    })
  })
})

describe('noConfigMessage', () => {
  it('names the resolved backend and points at config init', () => {
    const message = noConfigMessage('file')
    expect(message).toContain('file')
    expect(message).toContain('vaultkeeper config init')
  })

  // Issue #98 acceptance criterion 2: the remediation hint must spell out
  // `--backend <type>` explicitly (never a bare `config init`), and the type it
  // names must be the same backend the fallback just reported — so following it
  // verbatim can never silently persist a different (e.g. OS-native) backend.
  it('spells out --backend with the resolved backend type, never a bare config init (issue #98)', () => {
    const message = noConfigMessage('file')
    expect(message).toContain('vaultkeeper config init --backend file')
  })
})
