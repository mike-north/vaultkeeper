/** Concurrent YubiKey writers share the encrypted-record inventory. */
import { describe, expect, it, vi } from 'vitest'
import { createCipheriv, createHash, hkdfSync } from 'node:crypto'
import {
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rename,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

/** Hold one directory snapshot after the actual filesystem read. */
interface IDirectorySnapshot {
  readonly dir: string
  readonly captured: () => void
  readonly release: Promise<void>
}

const { legacyReadRace, directoryRace } = vi.hoisted(() => {
  const directoryRace: { snapshot: IDirectorySnapshot | undefined } = { snapshot: undefined }
  return { legacyReadRace: { active: false }, directoryRace }
})

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
    readdir: async (dir: string, options: { withFileTypes: true }) => {
      const entries = await actual.readdir(dir, options)
      const snapshot = directoryRace.snapshot
      if (snapshot?.dir === dir) {
        directoryRace.snapshot = undefined
        snapshot.captured()
        await snapshot.release
      }
      return entries
    },
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
import { DecryptionError, FilesystemError, SecretNotFoundError } from '../../../src/errors.js'

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
async function writeLegacyAlias(dir: string, id = '\ud800'): Promise<string> {
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
  it.skipIf(process.platform === 'win32')(
    'publishes a regular record over a symlink without touching its target',
    async () => {
      const dir = await mkdtemp(join(tmpdir(), 'vk-yubikey-inventory-'))
      try {
        const target = join(dir, 'unrelated')
        const record = join(dir, '7a.enc')
        await writeFile(target, 'keep this file')
        await symlink(target, record)
        await new YubikeyBackend(dir).store('z', 'value')

        const reopened = new YubikeyBackend(dir)
        expect(await reopened.list()).toEqual(['z'])
        expect(await reopened.retrieve('z')).toBe('value')
        expect((await lstat(record)).isFile()).toBe(true)
        expect(await readFile(target, 'utf8')).toBe('keep this file')
      } finally {
        await rm(dir, { recursive: true, force: true })
      }
    },
  )

  it.skipIf(process.platform === 'win32')(
    'lists a legacy record stored through a symlink',
    async () => {
      const dir = await mkdtemp(join(tmpdir(), 'vk-yubikey-inventory-'))
      try {
        const target = join(dir, 'legacy-target')
        const record = join(dir, '7a.enc')
        await new YubikeyBackend(dir).store('z', 'value')
        await rename(record, target)
        await symlink(target, record)
        await symlink(dir, join(dir, '61.enc'))
        await symlink(join(dir, 'missing'), join(dir, '62.enc'))
        await symlink(join(target, 'child'), join(dir, '63.enc'))

        const reopened = new YubikeyBackend(dir)
        expect(await reopened.retrieve('z')).toBe('value')
        expect(await reopened.list()).toEqual(['z'])
        await reopened.delete('z')
        expect(await reopened.list()).toEqual([])
        expect((await lstat(target)).isFile()).toBe(true)
      } finally {
        await rm(dir, { recursive: true, force: true })
      }
    },
  )

  it('lists a successful overwrite after the record was renamed to uppercase', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'vk-yubikey-inventory-'))
    try {
      const backend = new YubikeyBackend(dir)
      await backend.store('z', 'old value')
      const canonical = join(dir, '7a.enc')
      const uppercase = join(dir, '7A.ENC')
      await rename(canonical, uppercase)
      const caseSensitive = await lstat(canonical).then(
        () => false,
        (err: unknown) => {
          expect(err).toMatchObject({ code: 'ENOENT' })
          return true
        },
      )
      const oldRecord = await readFile(uppercase)
      const beforeOverwrite = new YubikeyBackend(dir)
      if (!caseSensitive) {
        expect(await beforeOverwrite.retrieve('z')).toBe('old value')
      }
      expect(await beforeOverwrite.list()).toEqual(caseSensitive ? [] : ['z'])
      await backend.store('z', 'new value')

      const reopened = new YubikeyBackend(dir)
      expect(await reopened.list()).toEqual(['z'])
      expect(await reopened.retrieve('z')).toBe('new value')
      await reopened.delete('z')
      expect(await reopened.list()).toEqual([])
      if (caseSensitive) {
        expect(await readFile(uppercase)).toEqual(oldRecord)
      }
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })

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

  it('lists a truncated indexed record so cleanup can still delete it', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'vk-yubikey-inventory-'))
    try {
      const backend = new YubikeyBackend(dir)
      await backend.store('alpha', 'first value')
      await backend.store('beta', 'second value')
      const beta = join(dir, '62657461.enc')
      await writeFile(
        join(dir, 'metadata.json'),
        JSON.stringify({ entries: { alpha: join(dir, '616c706861.enc'), beta } }),
      )
      await writeFile(beta, (await readFile(beta)).subarray(0, 12))

      const reopened = new YubikeyBackend(dir)
      expect(await reopened.exists('beta')).toBe(true)
      await expect(reopened.retrieve('beta')).rejects.toBeInstanceOf(DecryptionError)
      expect((await reopened.list()).sort()).toEqual(['alpha', 'beta'])
      await reopened.delete('beta')
      expect(await reopened.list()).toEqual(['alpha'])
      await expect(lstat(beta)).rejects.toMatchObject({ code: 'ENOENT' })
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })

  it('lists a truncated compact record by its exact filename for cleanup', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'vk-yubikey-inventory-'))
    try {
      const id = 'a\ud800\ufffdb'
      const record = join(dir, '61eda080efbfbd62.vk2')
      await new YubikeyBackend(dir).store(id, 'value')
      await writeFile(record, (await readFile(record)).subarray(0, 12))
      const reopened = new YubikeyBackend(dir)
      await expect(reopened.retrieve(id)).rejects.toBeInstanceOf(DecryptionError)
      expect(await reopened.list()).toEqual([id])
      await reopened.delete(id)
      expect(await reopened.list()).toEqual([])
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })

  it.skipIf(process.platform === 'win32')(
    'resolves only possible compact record names during inventory',
    async () => {
      const dir = await mkdtemp(join(tmpdir(), 'vk-yubikey-inventory-'))
      try {
        const backend = new YubikeyBackend(dir)
        await backend.store('alpha', 'value')
        const overlong = 'a'.repeat(300)
        await symlink(overlong, join(dir, '61.vk2'))
        await symlink(overlong, join(dir, 'ffefbfbd.vk2'))
        expect(await backend.list()).toEqual(['alpha'])

        const candidate = join(dir, 'eda080.vk2')
        await symlink(overlong, candidate)
        await expect(backend.list()).rejects.toMatchObject({
          code: 'ENAMETOOLONG',
          path: candidate,
        })
      } finally {
        await rm(dir, { recursive: true, force: true })
      }
    },
  )

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

  it('reports an unrecoverable legacy spelling after index corruption', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'vk-yubikey-inventory-'))
    try {
      const id = await writeLegacyAlias(dir)
      expect(await new YubikeyBackend(dir).list()).toEqual([id])
      await writeFile(join(dir, 'metadata.json'), '{broken')

      const reopened = new YubikeyBackend(dir)
      for (const operation of [
        () => reopened.list(),
        () => reopened.exists(id),
        () => reopened.retrieve('\ufffd'),
        () => reopened.delete(id),
      ]) {
        const result = operation()
        await expect(result).rejects.toBeInstanceOf(DecryptionError)
        await expect(result).rejects.toThrow(/ambiguous.*legacy/i)
        await expect(result).rejects.toHaveProperty('path', join(dir, 'efbfbd.enc'))
      }
      expect((await lstat(join(dir, 'efbfbd.enc'))).isFile()).toBe(true)
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })

  it('reports ambiguity when the index claims two spellings for one legacy record', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'vk-yubikey-inventory-'))
    try {
      const id = await writeLegacyAlias(dir)
      const entry = join(dir, 'efbfbd.enc')
      await writeFile(
        join(dir, 'metadata.json'),
        JSON.stringify({ entries: { [id]: entry, '\ufffd': entry } }),
      )
      const reopened = new YubikeyBackend(dir)
      await expect(reopened.list()).rejects.toBeInstanceOf(DecryptionError)
      await expect(reopened.retrieve('\ufffd')).rejects.toBeInstanceOf(DecryptionError)
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })

  it('rejects an indexed spelling whose path points to a different legacy file', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'vk-yubikey-inventory-'))
    try {
      await writeLegacyAlias(dir)
      const record = join(dir, 'efbfbd.enc')
      const original = await readFile(record)
      await writeFile(
        join(dir, 'metadata.json'),
        JSON.stringify({ entries: { '\ufffd': 'unrelated.enc' } }),
      )
      const backend = new YubikeyBackend(dir)
      await expect(backend.list()).rejects.toBeInstanceOf(DecryptionError)
      await expect(backend.store('\ufffd', 'new value')).rejects.toBeInstanceOf(DecryptionError)
      expect(await readFile(record)).toEqual(original)
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })

  it('keeps a legacy record listed while another instance upgrades its filename', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'vk-yubikey-inventory-'))
    let resume: () => void = () => undefined
    try {
      const id = await writeLegacyAlias(dir)
      let captured: () => void = () => undefined
      const ready = new Promise<void>((resolve) => {
        captured = resolve
      })
      const release = new Promise<void>((resolve) => {
        resume = resolve
      })
      directoryRace.snapshot = { dir, captured, release }
      const inventory = new YubikeyBackend(dir).list()
      await ready
      await new YubikeyBackend(dir).store(id, 'new value')
      resume()
      await expect(inventory).resolves.toEqual([id])
    } finally {
      directoryRace.snapshot = undefined
      resume()
      await rm(dir, { recursive: true, force: true })
    }
  })

  it.skipIf(process.platform !== 'darwin')(
    'stores short IDs at the macOS path boundary',
    async () => {
      const dir = await mkdtemp(join(tmpdir(), 'vk-yubikey-inventory-'))
      try {
        const maxDirBytes = 1016 // The canonical /7a.enc suffix uses seven of 1023 bytes.
        let storage = await realpath(dir)
        while (Buffer.byteLength(storage) < maxDirBytes) {
          const remaining = maxDirBytes - Buffer.byteLength(storage) - 1
          storage = join(storage, 'a'.repeat(remaining === 201 ? 199 : Math.min(remaining, 200)))
        }
        await mkdir(storage, { recursive: true })
        await writeFile(join(storage, '7a.enc'), 'existing record path')
        await new YubikeyBackend(storage).store('z', 'value')
        const reopened = new YubikeyBackend(storage)
        expect(await reopened.list()).toEqual(['z'])
        expect(await reopened.retrieve('z')).toBe('value')
      } finally {
        await rm(dir, { recursive: true, force: true })
      }
    },
  )

  it.skipIf(process.platform !== 'darwin')(
    'provisions fresh distinct IDs when their hashed paths cannot fit',
    async () => {
      const dir = await mkdtemp(join(tmpdir(), 'vk-yubikey-inventory-'))
      try {
        let storage = await realpath(dir)
        while (Buffer.byteLength(storage) < 995) {
          const remaining = 994 - Buffer.byteLength(storage)
          storage = join(storage, 'a'.repeat(remaining === 201 ? 199 : Math.min(remaining, 200)))
        }
        const id = '\ufffd'
        const alias = '\ud800'
        const backend = new YubikeyBackend(storage)
        await backend.store('alpha', 'first value')
        await Promise.all([backend.store(id, 'replacement'), backend.store(alias, 'surrogate')])

        const reopened = new YubikeyBackend(storage)
        expect((await reopened.list()).sort()).toEqual(['alpha', alias, id].sort())
        expect(await reopened.retrieve(id)).toBe('replacement')
        expect(await reopened.retrieve(alias)).toBe('surrogate')
        expect(await reopened.exists(id)).toBe(true)
        await reopened.delete(id)
        expect(await reopened.exists(id)).toBe(false)
        expect(await reopened.retrieve(alias)).toBe('surrogate')
      } finally {
        await rm(dir, { recursive: true, force: true })
      }
    },
  )

  it.skipIf(process.platform !== 'darwin')(
    'preserves a confirmed legacy ID while provisioning a distinct alias at the path boundary',
    async () => {
      const dir = await mkdtemp(join(tmpdir(), 'vk-yubikey-inventory-'))
      try {
        let storage = await realpath(dir)
        while (Buffer.byteLength(storage) < 995) {
          const remaining = 994 - Buffer.byteLength(storage)
          storage = join(storage, 'a'.repeat(remaining === 201 ? 199 : Math.min(remaining, 200)))
        }
        await mkdir(storage, { recursive: true })
        const id = await writeLegacyAlias(storage, '\ufffd')
        const backend = new YubikeyBackend(storage)
        await backend.store('\ud800', 'different ID')
        expect(await backend.retrieve(id)).toBe('value')
        expect(await backend.retrieve('\ud800')).toBe('different ID')
        await backend.delete('\ud800')
        await backend.store(id, 'new value')

        const reopened = new YubikeyBackend(storage)
        expect(await reopened.list()).toEqual([id])
        expect(await reopened.retrieve(id)).toBe('new value')
        await reopened.delete(id)
        expect(await reopened.list()).toEqual([])
        await reopened.store(id, 'new credential')
        expect(await reopened.list()).toEqual([id])
        expect(await reopened.retrieve(id)).toBe('new credential')
      } finally {
        await rm(dir, { recursive: true, force: true })
      }
    },
  )

  it.skipIf(process.platform !== 'darwin')(
    'deletes a legacy record when its exact path cannot fit',
    async () => {
      const dir = await mkdtemp(join(tmpdir(), 'vk-yubikey-inventory-'))
      try {
        let storage = await realpath(dir)
        while (Buffer.byteLength(storage) < 1008) {
          const remaining = 1007 - Buffer.byteLength(storage)
          storage = join(storage, 'a'.repeat(remaining === 201 ? 199 : Math.min(remaining, 200)))
        }
        await mkdir(storage, { recursive: true })
        const id = await writeLegacyAlias(storage)
        const backend = new YubikeyBackend(storage)
        expect(await backend.list()).toEqual([id])
        expect(await backend.retrieve(id)).toBe('value')
        await expect(backend.delete(id)).resolves.toBeUndefined()
        expect(await backend.list()).toEqual([])
      } finally {
        await rm(dir, { recursive: true, force: true })
      }
    },
  )

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

  it('reads and retires an older hashed record after publishing its compact replacement', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'vk-yubikey-inventory-'))
    try {
      const id = '\ufffd'
      const digest = createHash('sha256').update(Buffer.from(id, 'utf16le')).digest('hex')
      const olderPath = join(dir, `id-${digest}.enc`)
      await new YubikeyBackend(dir).store(id, 'old value')
      await rename(join(dir, 'efbfbd.vk2'), olderPath)

      const reopened = new YubikeyBackend(dir)
      expect(await reopened.list()).toEqual([id])
      expect(await reopened.exists(id)).toBe(true)
      expect(await reopened.retrieve(id)).toBe('old value')
      await reopened.store(id, 'new value')
      await expect(lstat(olderPath)).rejects.toMatchObject({ code: 'ENOENT' })
      expect(await reopened.retrieve(id)).toBe('new value')
      await reopened.delete(id)
      expect(await reopened.exists(id)).toBe(false)
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })

  it.skipIf(process.platform !== 'darwin')(
    'refuses to overwrite or delete an older record that is present beyond the path limit',
    async () => {
      const temp = await mkdtemp(join(tmpdir(), 'vk-yubikey-inventory-'))
      try {
        const dir = await realpath(temp)
        const short = join(dir, 'short')
        const id = '\ufffd'
        const digest = createHash('sha256').update(Buffer.from(id, 'utf16le')).digest('hex')
        const oldName = `id-${digest}.enc`
        await new YubikeyBackend(short).store(id, 'old value')
        await rename(join(short, 'efbfbd.vk2'), join(short, oldName))
        let parent = dir
        while (Buffer.byteLength(parent) < 990) {
          const remaining = 989 - Buffer.byteLength(parent)
          parent = join(parent, 'a'.repeat(remaining === 201 ? 199 : Math.min(remaining, 200)))
        }
        await mkdir(parent, { recursive: true })
        const long = join(parent, 'long')
        await rename(short, long)
        try {
          const cramped = new YubikeyBackend(long)
          const failure = { code: 'ENAMETOOLONG', path: join(long, oldName) }
          await expect(cramped.exists(id)).rejects.toMatchObject(failure)
          await expect(cramped.retrieve(id)).rejects.toMatchObject(failure)
          await expect(cramped.store(id, 'new value')).rejects.toMatchObject(failure)
          await expect(cramped.delete(id)).rejects.toMatchObject(failure)
          await expect(lstat(join(long, 'efbfbd.vk2'))).rejects.toMatchObject({ code: 'ENOENT' })
        } finally {
          await rename(long, short)
        }
        const reopened = new YubikeyBackend(short)
        expect(await reopened.list()).toEqual([id])
        expect(await reopened.retrieve(id)).toBe('old value')
      } finally {
        await rm(temp, { recursive: true, force: true })
      }
    },
  )

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
      await writeFile(join(dir, 'metadata.json'), '{broken')

      const reopened = new YubikeyBackend(dir)
      expect(await reopened.list()).toEqual([id])
      expect(await reopened.retrieve(id)).toBe('new value')
      await expect(reopened.retrieve('\ufffd')).rejects.toBeInstanceOf(SecretNotFoundError)
      await reopened.delete(id)
      expect(await reopened.list()).toEqual([])
      expect(await reopened.exists(id)).toBe(false)
      await expect(lstat(join(dir, 'efbfbd.enc'))).rejects.toMatchObject({ code: 'ENOENT' })
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })

  it('deletes an exact record while preserving a directory at the legacy filename', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'vk-yubikey-inventory-'))
    try {
      const id = '\ufffd'
      const legacyPath = join(dir, 'efbfbd.enc')
      await mkdir(legacyPath)
      const backend = new YubikeyBackend(dir)
      await backend.store(id, 'value')
      expect(await backend.list()).toEqual([id])
      await backend.delete(id)
      expect(await backend.list()).toEqual([])
      expect((await lstat(legacyPath)).isDirectory()).toBe(true)
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
