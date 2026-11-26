import { describe, it, expect, vi, beforeEach } from 'vitest'
import * as path from 'node:path'

vi.mock('../../../../vaultkeeper-wasm/host/trust-lock.js', () => ({
  lockTrustManifest: vi.fn(() => Promise.resolve(() => undefined)),
}))

vi.mock('node:fs/promises', () => ({
  readFile: vi.fn(),
  mkdir: vi.fn(),
  writeFile: vi.fn(),
  unlink: vi.fn().mockResolvedValue(undefined),
  rename: vi.fn(),
}))

import * as fs from 'node:fs/promises'
import { loadManifest, saveManifest } from '../../../src/identity/manifest.js'
import { FilesystemError } from '../../../src/errors.js'

const mockFs = vi.mocked(fs)

/** Build a Node.js-shaped filesystem error with a `code` (e.g. 'EACCES'). */
function fsError(code: string, message: string): NodeJS.ErrnoException {
  return Object.assign(new Error(message), { code })
}

// ---------------------------------------------------------------------------
// Regression: issue #133 review — loadManifest/saveManifest constructed
// FilesystemError from a caught fs error without passing it through as
// `cause`, so `.code` stayed undefined and `.cause` was absent for these
// paths even though every other FilesystemError construction site in the
// package does propagate it.
// ---------------------------------------------------------------------------

describe('loadManifest (errno propagation)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('should preserve the errno code and cause on a non-ENOENT read failure', async () => {
    const permError = fsError('EACCES', 'permission denied')
    mockFs.readFile.mockRejectedValueOnce(permError)

    let caught: unknown
    try {
      await loadManifest('/fake')
    } catch (err) {
      caught = err
    }

    expect(caught).toBeInstanceOf(FilesystemError)
    if (caught instanceof FilesystemError) {
      expect(caught.path).toBe(path.join('/fake', 'trust-manifest.json'))
      expect(caught.permission).toBe('read')
      expect(caught.code).toBe('EACCES')
      expect(caught.cause).toBe(permError)
    }
  })

  it('should preserve the original SyntaxError as cause when the manifest is not valid JSON (code stays undefined — not an errno failure)', async () => {
    mockFs.readFile.mockResolvedValueOnce('not valid json!!')

    let caught: unknown
    try {
      await loadManifest('/fake')
    } catch (err) {
      caught = err
    }

    expect(caught).toBeInstanceOf(FilesystemError)
    if (caught instanceof FilesystemError) {
      expect(caught.code).toBeUndefined()
      expect(caught.cause).toBeInstanceOf(SyntaxError)
    }
  })
})

describe('saveManifest (errno propagation)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('reports a directory creation failure at the config directory', async () => {
    const error = fsError('EACCES', 'permission denied')
    mockFs.mkdir.mockRejectedValueOnce(error)
    await expect(saveManifest('/fake', new Map())).rejects.toMatchObject({
      path: '/fake',
      permission: 'create',
      code: 'EACCES',
      cause: error,
    })
    expect(mockFs.writeFile).not.toHaveBeenCalled()
  })

  it('should preserve the errno code and cause on a write failure', async () => {
    const noSpaceError = fsError('ENOSPC', 'no space left on device')
    mockFs.writeFile.mockRejectedValueOnce(noSpaceError)

    let caught: unknown
    try {
      await saveManifest('/fake', new Map())
    } catch (err) {
      caught = err
    }

    expect(caught).toBeInstanceOf(FilesystemError)
    if (caught instanceof FilesystemError) {
      expect(caught.permission).toBe('write')
      expect(caught.code).toBe('ENOSPC')
      expect(caught.cause).toBe(noSpaceError)
    }
  })

  it('cleans up the unpublished file and preserves the rename failure', async () => {
    const renameError = fsError('EACCES', 'permission denied')
    mockFs.writeFile.mockResolvedValueOnce(undefined)
    mockFs.rename.mockRejectedValueOnce(renameError)

    await expect(saveManifest('/fake', new Map())).rejects.toMatchObject({
      path: path.join('/fake', 'trust-manifest.json'),
      permission: 'write',
      code: 'EACCES',
      cause: renameError,
    })
    const temporaryPath = mockFs.rename.mock.calls[0]?.[0]
    expect(temporaryPath).toBeDefined()
    expect(mockFs.unlink).toHaveBeenCalledWith(temporaryPath)
  })
})
