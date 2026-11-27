/** Concurrent YubiKey writers share the encrypted-record inventory. */
import { describe, expect, it, vi } from 'vitest'
import { createCipheriv, hkdfSync } from 'node:crypto'
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const { legacyReadRace } = vi.hoisted(() => ({ legacyReadRace: { active: false } }))

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
      if (!legacyReadRace.active || !file.endsWith('metadata.json')) {
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

/** Produce the shared GCM fields for legacy YubiKey and ordinary file fixtures. */
function encryptFixture(key: Buffer, iv: Buffer): string {
  try {
    const cipher = createCipheriv('aes-256-gcm', key, iv)
    const ciphertext = Buffer.concat([cipher.update('value', 'utf8'), cipher.final()])
    return [iv, cipher.getAuthTag(), ciphertext].map((part) => part.toString('base64')).join(':')
  } finally {
    key.fill(0)
  }
}

/** A pre-upgrade record whose exact UTF-16 spelling lived only in the shared index. */
async function writeLegacyAlias(dir: string): Promise<string> {
  const id = '\ud800'
  const entryPath = join(dir, 'efbfbd.enc')
  const key = Buffer.from(
    hkdfSync(
      'sha256',
      Buffer.from('deadbeefcafe01234567deadbeefcafe01234567', 'hex'),
      Buffer.alloc(0),
      Buffer.from(`vaultkeeper-yubikey:${id}`),
      32,
    ),
  )
  await writeFile(entryPath, `1:${encryptFixture(key, Buffer.alloc(12, 0x42))}`)
  await writeFile(join(dir, 'metadata.json'), JSON.stringify({ entries: { [id]: entryPath } }))
  return id
}

describe('YubiKey inventory', () => {
  it('excludes records belonging to the file backend and directories', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'vk-yubikey-inventory-'))
    try {
      // A valid FileBackend IV can be all digits after Base64 encoding.
      const iv = Buffer.from('1234567890123456', 'base64')
      await writeFile(join(dir, '.key'), Buffer.alloc(32, 0x42))
      await writeFile(join(dir, '666f726569676e.enc'), encryptFixture(Buffer.alloc(32, 0x42), iv))
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
      const id = await writeLegacyAlias(dir)
      const reopened = new YubikeyBackend(dir)
      expect(await reopened.list()).toEqual([id])
      expect(await reopened.retrieve(id)).toBe('value')
      await reopened.delete(id)
      expect(await reopened.list()).toEqual([])
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })

  it('lists the exact spelling of a newly stored unpaired surrogate without legacy metadata', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'vk-yubikey-inventory-'))
    try {
      const id = '\ud800'
      await new YubikeyBackend(dir).store(id, 'value')
      const reopened = new YubikeyBackend(dir)
      expect(await reopened.list()).toEqual([id])
      expect(await reopened.retrieve(id)).toBe('value')
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })

  it('keeps a newly stored U+FFFD ID when stale legacy metadata maps its filename to an alias', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'vk-yubikey-inventory-'))
    try {
      const legacyId = await writeLegacyAlias(dir)
      const id = '\ufffd'
      await new YubikeyBackend(dir).store(id, 'new value')
      const reopened = new YubikeyBackend(dir)
      expect((await reopened.list()).sort()).toEqual([legacyId, id].sort())
      expect(await reopened.retrieve(id)).toBe('new value')
      expect(await reopened.retrieve(legacyId)).toBe('value')
      await reopened.delete(id)
      expect(await reopened.list()).toEqual([legacyId])
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })

  it('keeps distinct concurrent stores whose IDs previously shared a UTF-8 filename', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'vk-yubikey-inventory-'))
    try {
      const ids = ['\ud800', '\ud801', '\ufffd']
      await Promise.all(
        ids.map((id, index) => new YubikeyBackend(dir).store(id, `value-${String(index)}`)),
      )
      const reopened = new YubikeyBackend(dir)
      expect((await reopened.list()).sort()).toEqual([...ids].sort())
      expect(await Promise.all(ids.map((id) => reopened.retrieve(id)))).toEqual([
        'value-0',
        'value-1',
        'value-2',
      ])
      await reopened.delete('\ud800')
      expect(await reopened.exists('\ud800')).toBe(false)
      expect(await reopened.retrieve('\ufffd')).toBe('value-2')
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })

  it('does not resurrect an older indexed version after deleting an upgraded alias', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'vk-yubikey-inventory-'))
    try {
      const id = await writeLegacyAlias(dir)
      const backend = new YubikeyBackend(dir)
      await backend.store(id, 'new value')
      expect(await backend.list()).toEqual([id])
      expect(await backend.retrieve(id)).toBe('new value')
      await backend.delete(id)
      expect(await backend.list()).toEqual([])
      expect(await backend.exists(id)).toBe(false)
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })

  it('deletes an exact record whose legacy filename exceeds filesystem limits', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'vk-yubikey-inventory-'))
    try {
      const id = '\ufffd'.repeat(50)
      await new YubikeyBackend(dir).store(id, 'value')
      const reopened = new YubikeyBackend(dir)
      expect(await reopened.list()).toEqual([id])
      expect(await reopened.retrieve(id)).toBe('value')
      await reopened.delete(id)
      expect(await reopened.exists(id)).toBe(false)
      expect(await reopened.list()).toEqual([])
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
      legacyReadRace.active = true
      await Promise.all([first.store('alpha', 'a'), second.store('beta', 'b')])
      legacyReadRace.active = false
      expect((await new YubikeyBackend(dir).list()).sort()).toEqual(['alpha', 'beta'])
      await writeFile(join(dir, 'metadata.json'), '{broken')
      expect((await new YubikeyBackend(dir).list()).sort()).toEqual(['alpha', 'beta'])
    } finally {
      legacyReadRace.active = false
      await rm(dir, { recursive: true, force: true })
    }
  })
})
