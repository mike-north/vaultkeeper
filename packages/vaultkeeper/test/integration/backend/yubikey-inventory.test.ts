/** Concurrent YubiKey writers share the encrypted-record inventory. */
import { describe, expect, it, vi } from 'vitest'
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

// Make both legacy index readers observe the same state before either writes.
vi.mock('node:fs/promises', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:fs/promises')>()
  let arrivals = 0
  let release: (() => void) | undefined
  const barrier = new Promise<void>((resolve) => {
    release = resolve
  })
  return {
    ...actual,
    readFile: async (file: string, encoding: BufferEncoding) => {
      if (!file.endsWith('metadata.json')) {
        return actual.readFile(file, encoding)
      }
      const result = await actual.readFile(file, encoding).then(
        (value) => ({ value }),
        (error: unknown) => ({ error }),
      )
      arrivals++
      if (arrivals === 2) {
        release?.()
      }
      await barrier
      if ('error' in result) {
        throw result.error
      }
      return result.value
    },
  }
})

vi.mock('../../../src/util/exec.js', () => ({
  execCommandFull: vi.fn((_command: string, args: string[]) =>
    Promise.resolve({
      exitCode: 0,
      stderr: '',
      stdout: args[0] === 'otp' ? 'deadbeefcafe01234567deadbeefcafe01234567' : 'device',
    }),
  ),
}))

import { YubikeyBackend } from '../../../src/backend/yubikey-backend.js'
import { FileBackend } from '../../../src/backend/file-backend.js'
import { FilesystemError } from '../../../src/errors.js'

describe('YubiKey inventory', () => {
  it('excludes records belonging to the file backend and directories', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'vk-yubikey-inventory-'))
    try {
      await new FileBackend(dir).store('foreign', 'value')
      await mkdir(join(dir, '616c706861.enc'))
      expect(await new YubikeyBackend(dir).list()).toEqual([])
      expect(await new FileBackend(dir).retrieve('foreign')).toBe('value')
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })

  it('preserves a legacy ID with an unpaired surrogate from metadata', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'vk-yubikey-inventory-'))
    try {
      const id = '\ud800'
      await new YubikeyBackend(dir).store(id, 'value')
      await writeFile(
        join(dir, 'metadata.json'),
        JSON.stringify({ entries: { [id]: join(dir, 'efbfbd.enc') } }),
      )
      expect(await new YubikeyBackend(dir).list()).toEqual([id])
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })
  it('reports an inaccessible inventory directory as a typed filesystem error', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'vk-yubikey-inventory-'))
    try {
      const file = join(dir, 'file')
      await writeFile(file, 'not a directory')
      const error: unknown = await new YubikeyBackend(file).list().catch((err: unknown) => err)
      expect(error).toBeInstanceOf(FilesystemError)
      if (error instanceof FilesystemError) {
        expect(error.path).toBe(file)
        expect(error.permission).toBe('read')
        expect(error.code).toBe('ENOTDIR')
      }
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })
  it('lists concurrent stores after reopen even if the legacy index is corrupt', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'vk-yubikey-inventory-'))
    try {
      const first = new YubikeyBackend(dir)
      const second = new YubikeyBackend(dir)
      await Promise.all([first.store('alpha', 'a'), second.store('beta', 'b')])
      expect((await new YubikeyBackend(dir).list()).sort()).toEqual(['alpha', 'beta'])
      await writeFile(join(dir, 'metadata.json'), '{broken')
      expect((await new YubikeyBackend(dir).list()).sort()).toEqual(['alpha', 'beta'])
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })
})
