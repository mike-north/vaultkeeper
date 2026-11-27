/** Ordinary file stores can use the full macOS path budget of their entry filenames. */
import * as fs from 'node:fs/promises'
import * as os from 'node:os'
import * as path from 'node:path'
import { describe, expect, it, vi } from 'vitest'
import { BackendRegistry } from '../../../src/index.js'

// Simulate another writer owning the first usable staging path.
const collision = vi.hoisted(() => ({ pending: false, occupiedPath: '' }))

/** On other hosts, model the macOS limit while keeping filesystem operations real. */
function checkPathLimit(...paths: fs.PathLike[]): void {
  if (
    process.platform !== 'darwin' &&
    paths.some((file) => Buffer.byteLength(String(file)) >= 1024)
  ) {
    throw Object.assign(new Error('path too long'), { code: 'ENAMETOOLONG' })
  }
}

vi.mock('node:fs/promises', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:fs/promises')>()
  return {
    ...actual,
    open: async (...args: Parameters<typeof actual.open>): Promise<fs.FileHandle> => {
      const [file, flags] = args
      checkPathLimit(file)
      if (
        collision.pending &&
        flags === 'wx' &&
        typeof file === 'string' &&
        Buffer.byteLength(file) < 1024
      ) {
        await actual.writeFile(file, 'other writer', { flag: 'wx', mode: 0o600 })
        collision.occupiedPath = file
        collision.pending = false
      }
      return actual.open(...args)
    },
    link: async (...args: Parameters<typeof actual.link>): Promise<void> => {
      checkPathLimit(...args)
      await actual.link(...args)
    },
    rename: async (...args: Parameters<typeof actual.rename>): Promise<void> => {
      checkPathLimit(...args)
      await actual.rename(...args)
    },
  }
})

/** Reach an exact byte length without exceeding the per-component name limit. */
function directoryAtByteLength(base: string, targetLength: number): string {
  let target = base
  while (Buffer.byteLength(target) < targetLength) {
    const remaining = targetLength - Buffer.byteLength(target) - 1
    const length = remaining === 201 ? 199 : Math.min(remaining, 200)
    target = path.join(target, 'a'.repeat(length))
  }
  return target
}

describe('ordinary file stores at the macOS path limit', () => {
  it.each([
    { length: 1010, id: 'a', state: 'fresh' },
    { length: 1010, id: 'a', state: 'corrupt' },
    { length: 1016, id: 'a', state: 'fresh' },
    { length: 1016, id: 'a', state: 'corrupt' },
    { length: 1016, id: 'a', state: 'interrupted repair' },
    { length: 1017, id: '', state: 'fresh' },
    { length: 1017, id: '', state: 'corrupt' },
    { length: 1018, id: '', state: 'fresh' },
    { length: 1018, id: '', state: 'corrupt' },
    { length: 1018, id: '', state: 'interrupted repair' },
    { length: 1018, id: '', state: 'fresh with stage collision' },
  ])(
    'stores and reopens ID "$id" in a $state store at $length bytes',
    async ({ length, id, state }) => {
      const root = await fs.mkdtemp(path.join(os.tmpdir(), 'vk-file-path-limit-'))
      try {
        // Resolve temp-root symlinks so kernel path expansion does not add bytes.
        const dir = directoryAtByteLength(await fs.realpath(root), length)
        expect(Buffer.byteLength(dir)).toBe(length)
        const keyPath = path.join(dir, '.key')
        const candidate = Buffer.alloc(32, 0x42)
        if (state === 'corrupt' || state === 'interrupted repair') {
          await fs.mkdir(dir, { recursive: true })
          await fs.writeFile(keyPath, Buffer.alloc(1), { mode: 0o600 })
        }
        if (state === 'interrupted repair') {
          await fs.writeFile(path.join(dir, '.k.r'), candidate, { mode: 0o600 })
        }
        collision.pending = state === 'fresh with stage collision'

        const config = { type: 'file', path: dir }
        await BackendRegistry.create('file', config).store(id, 'fixture')
        expect(await BackendRegistry.create('file', config).retrieve(id)).toBe('fixture')
        expect((await fs.stat(keyPath)).size).toBe(32)
        if (state === 'fresh with stage collision') {
          expect(await fs.readFile(collision.occupiedPath, 'utf8')).toBe('other writer')
          await fs.unlink(collision.occupiedPath)
        }
        expect((await fs.readdir(dir)).sort()).toEqual(
          id === '' ? ['.enc', '.key'] : ['.key', '61.enc'],
        )
        if (state === 'interrupted repair') {
          expect(await fs.readFile(keyPath)).toEqual(candidate)
        }
      } finally {
        collision.pending = false
        collision.occupiedPath = ''
        await fs.rm(root, { recursive: true, force: true })
      }
    },
  )
})
