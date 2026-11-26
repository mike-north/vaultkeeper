/** Concurrent YubiKey writers share the encrypted-record inventory. */
import { describe, expect, it, vi } from 'vitest'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
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

describe('YubiKey inventory', () => {
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
