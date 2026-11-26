/** File-backed secret storage must work on filesystems without hard links. */
import * as fs from 'node:fs/promises'
import * as os from 'node:os'
import * as path from 'node:path'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { FileBackend } from '../../../src/backend/file-backend.js'
import { FilesystemError } from '../../../src/errors.js'

vi.mock('node:fs/promises', async (importOriginal) => ({
  ...(await importOriginal<typeof import('node:fs/promises')>()),
  link: vi.fn(),
}))

beforeEach(() => {
  vi.mocked(fs.link)
    .mockReset()
    .mockRejectedValue(Object.assign(new Error('unsupported'), { code: 'ENOTSUP' }))
})

describe('file backend without hard links', () => {
  it.each(['EPERM', 'EISDIR'])('stores an ordinary secret when link reports %s', async (code) => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'vk-no-hardlinks-'))
    const platform = process.platform
    try {
      // On Windows, libuv can report EISDIR for a hard link on exFAT.
      if (code === 'EISDIR') Object.defineProperty(process, 'platform', { value: 'win32' })
      vi.mocked(fs.link).mockRejectedValue(Object.assign(new Error('link denied'), { code }))
      await new FileBackend(dir).store('example', 'value')
      expect(await new FileBackend(dir).retrieve('example')).toBe('value')
    } finally {
      Object.defineProperty(process, 'platform', { value: platform })
      await fs.rm(dir, { recursive: true, force: true })
    }
  })

  it.each(['fresh', 'repair'])(
    'stores and retrieves an ordinary secret in a %s store',
    async (state) => {
      const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'vk-no-hardlinks-'))
      try {
        if (state === 'repair') await fs.writeFile(path.join(dir, '.key'), Buffer.alloc(1))
        const backend = new FileBackend(dir)
        await backend.store('example', 'value')
        expect(await new FileBackend(dir).retrieve('example')).toBe('value')
      } finally {
        await fs.rm(dir, { recursive: true, force: true })
      }
    },
  )

  it('requires atomic wrapping-key publication even if the signing subdirectory supports links', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'vk-no-hardlinks-'))
    try {
      // A signing subdirectory can reside on a different filesystem from the wrapping key.
      const actual = await vi.importActual<typeof fs>('node:fs/promises')
      vi.mocked(fs.link)
        .mockRejectedValueOnce(Object.assign(new Error('unsupported'), { code: 'ENOTSUP' }))
        .mockImplementation(actual.link)
      const backend = new FileBackend(dir)
      const result: unknown = await backend
        .generateSigningKey('signing-key:test', 'EdDSA')
        .catch((error: unknown) => error)
      expect(result).toBeInstanceOf(FilesystemError)
      expect(result).toMatchObject({ code: 'ENOTSUP' })
      await expect(fs.stat(path.join(dir, '.key'))).rejects.toMatchObject({ code: 'ENOENT' })
      expect(await fs.readdir(path.join(dir, 'signing-keys'))).toEqual([])
    } finally {
      await fs.rm(dir, { recursive: true, force: true })
    }
  })
})
