/** File-backed secret storage must work on filesystems without hard links. */
import * as fs from 'node:fs/promises'
import * as os from 'node:os'
import * as path from 'node:path'
import { describe, expect, it, vi } from 'vitest'
import { FileBackend } from '../../../src/backend/file-backend.js'

vi.mock('node:fs/promises', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:fs/promises')>()
  return {
    ...actual,
    link: vi.fn().mockRejectedValue(Object.assign(new Error('unsupported'), { code: 'ENOTSUP' })),
  }
})

describe('file backend without hard links', () => {
  it('stores and retrieves an ordinary secret in a fresh directory', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'vk-no-hardlinks-'))
    try {
      const backend = new FileBackend(dir)
      await backend.store('example', 'value')
      expect(await new FileBackend(dir).retrieve('example')).toBe('value')
    } finally {
      await fs.rm(dir, { recursive: true, force: true })
    }
  })
})
