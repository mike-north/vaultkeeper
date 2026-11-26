import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import * as os from 'node:os'
import * as path from 'node:path'

// This suite needs a mocked node:fs/promises so it can force fs.access to
// fail with a non-ENOENT code (EACCES) without depending on real filesystem
// permission behavior, which is unreliable across platforms/CI users (e.g.
// root bypasses permission bits). All other config.test.ts suites use the
// real filesystem via temp dirs; this one is isolated in its own file so the
// mock doesn't leak into those.
vi.mock('node:fs/promises', async () => {
  const actual = await vi.importActual<typeof import('node:fs/promises')>('node:fs/promises')
  return {
    ...actual,
    access: vi.fn(),
    writeFile: vi.fn(actual.writeFile),
  }
})

const { access, writeFile, mkdtemp, rm } = await import('node:fs/promises')
const { configCommand } = await import('../../../src/commands/config.js')

/** Build a Node.js-shaped filesystem error with a `code` (e.g. 'EACCES'). */
function fsError(code: string, message: string): NodeJS.ErrnoException {
  return Object.assign(new Error(message), { code })
}

describe('config init: non-ENOENT access errors (regression: PR #105 review)', () => {
  let tempDir: string
  let configDir: string

  beforeEach(async () => {
    tempDir = await mkdtemp(path.join(os.tmpdir(), 'vaultkeeper-config-init-access-test-'))
    configDir = path.join(tempDir, '.config', 'vaultkeeper')
  })

  afterEach(async () => {
    vi.mocked(access).mockReset()
    vi.mocked(writeFile).mockClear()
    await rm(tempDir, { recursive: true, force: true })
  })

  // Before this fix, configInit's existence check treated ANY fs.access
  // failure (not just ENOENT) as "file doesn't exist", so an EACCES on the
  // config path would be silently swallowed and init would proceed to
  // writeFile — a less-direct failure mode that could attempt to overwrite
  // a file in an unusual permission state. It must now rethrow non-ENOENT
  // errors and never reach writeFile.
  it('rethrows an EACCES access error instead of proceeding to writeFile', async () => {
    vi.mocked(access).mockRejectedValue(fsError('EACCES', 'permission denied'))

    const code = await configCommand(['init'], configDir)

    expect(code).toBe(1)
    expect(vi.mocked(writeFile)).not.toHaveBeenCalled()
  })

  it('does not swallow an EPERM access error either', async () => {
    vi.mocked(access).mockRejectedValue(fsError('EPERM', 'operation not permitted'))

    const code = await configCommand(['init'], configDir)

    expect(code).toBe(1)
    expect(vi.mocked(writeFile)).not.toHaveBeenCalled()
  })
})
