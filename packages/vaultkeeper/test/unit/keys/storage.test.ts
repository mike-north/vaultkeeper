/**
 * Unit tests for persisted KeyManager state (`keys/storage.ts`).
 *
 * Verifies the acceptance-criteria contract for issue #59:
 * - key material persists across "processes" (independent load calls),
 * - it is encrypted at rest (never written as plaintext JSON),
 * - the on-disk files are owner-only (mode 0600),
 * - an expired grace period is dropped on load,
 * - a tampered/corrupt envelope degrades to "no state" rather than crashing.
 *
 * @see https://github.com/mike-north/vaultkeeper/issues/59
 */
import * as fs from 'node:fs/promises'
import * as os from 'node:os'
import * as path from 'node:path'
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { FilesystemError } from '../../../src/errors.js'
import { loadKeyState, saveKeyState } from '../../../src/keys/storage.js'
import type { KeyMaterial, KeyStateSnapshot } from '../../../src/keys/types.js'

const renameBarrier = vi.hoisted(() => ({
  enabled: false,
  pending: new Array<{ source: string; release: (fail?: boolean) => void }>(),
}))

// Faults apply only to the next exclusively created key-state staging file.
const stageFault = vi.hoisted(() => ({
  write: false,
  close: false,
  path: '',
  writeError: Object.assign(new Error('disk full'), { code: 'ENOSPC' }),
  closeError: Object.assign(new Error('close failed'), { code: 'EIO' }),
}))

// Model macOS's path limit on all platforms so the boundary stays tested in CI.
const pathLimit = vi.hoisted(() => ({ enabled: false }))

vi.mock('node:fs/promises', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:fs/promises')>()
  return {
    ...actual,
    open: async (...args: Parameters<typeof actual.open>): Promise<fs.FileHandle> => {
      if (pathLimit.enabled && args[1] === 'wx' && Buffer.byteLength(String(args[0])) >= 1024) {
        throw Object.assign(new Error('path too long'), { code: 'ENAMETOOLONG' })
      }
      const handle = await actual.open(...args)
      if (args[1] === 'wx' && (stageFault.write || stageFault.close)) {
        stageFault.path = String(args[0])
        if (stageFault.write) {
          vi.spyOn(handle, 'writeFile').mockImplementation(async () => {
            await handle.write('partial')
            throw stageFault.writeError
          })
        }
        if (stageFault.close) {
          const close = handle.close.bind(handle)
          vi.spyOn(handle, 'close').mockImplementation(async () => {
            await close()
            throw stageFault.closeError
          })
        }
      }
      return handle
    },
    rename: async (...args: Parameters<typeof actual.rename>): Promise<void> => {
      if (renameBarrier.enabled) {
        const fail = await new Promise<boolean>((resolve) => {
          renameBarrier.pending.push({
            source: String(args[0]),
            release: (fail = false) => {
              resolve(fail)
            },
          })
        })
        if (fail) {
          await actual.rename(args[0], path.join(String(args[1]), 'missing', 'keys.enc'))
          return
        }
      }
      await actual.rename(...args)
    },
  }
})

const CREATED_AT = new Date('2024-01-15T10:30:00.000Z')

function makeKey(id: string, byte: number): KeyMaterial {
  return { id, key: new Uint8Array(32).fill(byte), createdAt: CREATED_AT }
}

let dir: string

beforeEach(async () => {
  dir = await fs.mkdtemp(path.join(os.tmpdir(), 'vk-keystore-'))
})

afterEach(async () => {
  stageFault.write = false
  stageFault.close = false
  stageFault.path = ''
  pathLimit.enabled = false
  await fs.rm(dir, { recursive: true, force: true })
})

describe('saveKeyState / loadKeyState round-trip', () => {
  it('saves and reloads at the macOS path boundary supported by the old staging name', async () => {
    let target = dir
    const targetLength = Buffer.byteLength(dir) === 989 ? 991 : Math.max(990, Buffer.byteLength(dir))
    while (Buffer.byteLength(target) < targetLength) {
      const remaining = targetLength - Buffer.byteLength(target) - 1
      const length = remaining === 201 ? 199 : Math.min(remaining, 200)
      target = path.join(target, 'a'.repeat(length))
    }
    expect(Buffer.byteLength(target)).toBe(targetLength)
    const snapshot = { current: makeKey('k-boundary', 0x42) }
    pathLimit.enabled = true
    await saveKeyState(target, snapshot)
    expect(await loadKeyState(target)).toEqual(snapshot)
  })
  it.each([
    { write: true, code: 'ENOSPC', cause: stageFault.writeError },
    { write: false, code: 'EIO', cause: stageFault.closeError },
  ])('preserves the primary staging error when write failure is $write', async ({ write, code, cause }) => {
    const initial = { current: makeKey('k-initial', 0x10) }
    await saveKeyState(dir, initial)
    stageFault.write = write
    stageFault.close = true

    const result = await saveKeyState(dir, { current: makeKey('k-next', 0x11) }).catch(
      (error: unknown) => error,
    )
    expect(result).toBeInstanceOf(FilesystemError)
    expect(result).toMatchObject({
      name: 'FilesystemError',
      code,
      cause,
      path: stageFault.path,
    })
    expect(path.dirname(stageFault.path)).toBe(dir)
    expect(path.basename(stageFault.path)).toMatch(/^\.[A-Za-z0-9_-]{12}$/)
    await expect(fs.stat(stageFault.path)).rejects.toMatchObject({ code: 'ENOENT' })
    expect(await loadKeyState(dir)).toEqual(initial)
  })
  it('persists the current key so a later load resolves the same id and bytes', async () => {
    const current = makeKey('k-1-aaaa', 0x11)
    await saveKeyState(dir, { current })

    const loaded = await loadKeyState(dir)
    expect(loaded?.current.id).toBe('k-1-aaaa')
    expect(loaded?.current.createdAt.toISOString()).toBe(CREATED_AT.toISOString())
    expect(Buffer.from(loaded?.current.key ?? new Uint8Array()).toString('hex')).toBe(
      Buffer.from(current.key).toString('hex'),
    )
  })

  it('returns undefined when no state file exists yet', async () => {
    expect(await loadKeyState(dir)).toBeUndefined()
  })

  it('persists the previous key and grace expiry while the grace period is active', async () => {
    const snapshot: KeyStateSnapshot = {
      current: makeKey('k-2-bbbb', 0x22),
      previous: makeKey('k-1-aaaa', 0x11),
      gracePeriodExpiresAt: Date.now() + 60_000,
    }
    await saveKeyState(dir, snapshot)

    const loaded = await loadKeyState(dir)
    expect(loaded?.previous?.id).toBe('k-1-aaaa')
    expect(loaded?.gracePeriodExpiresAt).toBe(snapshot.gracePeriodExpiresAt)
  })

  it('publishes each complete snapshot from its own staging file', async () => {
    const initial = { current: makeKey('k-initial', 0x10) }
    const first = { current: makeKey('k-first', 0x11) }
    const second = { current: makeKey('k-second', 0x22) }
    await saveKeyState(dir, initial)

    renameBarrier.enabled = true
    const saves: Promise<void>[] = []
    try {
      saves.push(saveKeyState(dir, first))
      await vi.waitFor(() => {
        expect(renameBarrier.pending).toHaveLength(1)
      })
      saves.push(saveKeyState(dir, second))
      await vi.waitFor(() => {
        expect(renameBarrier.pending).toHaveLength(2)
      })

      expect(await loadKeyState(dir)).toEqual(initial)
      const [firstStage, secondStage] = renameBarrier.pending
      expect(firstStage).toBeDefined()
      expect(secondStage).toBeDefined()

      firstStage?.release()
      await saves[0]
      expect(await loadKeyState(dir)).toEqual(first)
      await expect(fs.stat(firstStage?.source ?? '')).rejects.toMatchObject({ code: 'ENOENT' })
      await expect(fs.stat(secondStage?.source ?? '')).resolves.toBeDefined()

      secondStage?.release()
      await saves[1]
      expect(await loadKeyState(dir)).toEqual(second)
      await expect(fs.stat(secondStage?.source ?? '')).rejects.toMatchObject({ code: 'ENOENT' })
    } finally {
      renameBarrier.enabled = false
      for (const stage of renameBarrier.pending.splice(0)) stage.release()
      await Promise.allSettled(saves)
    }
  })

  it('cleans up a failed rename while leaving the other save staged', async () => {
    const initial = { current: makeKey('k-initial', 0x10) }
    const next = { current: makeKey('k-next', 0x11) }
    await saveKeyState(dir, initial)

    renameBarrier.enabled = true
    const saves = [saveKeyState(dir, next), saveKeyState(dir, next)]
    const completed = Promise.allSettled(saves)
    try {
      await vi.waitFor(() => {
        expect(renameBarrier.pending).toHaveLength(2)
      })
      const [failedStage, survivingStage] = renameBarrier.pending
      failedStage?.release(true)
      await vi.waitFor(async () => {
        await expect(fs.stat(failedStage?.source ?? '')).rejects.toMatchObject({ code: 'ENOENT' })
      })
      await expect(fs.stat(survivingStage?.source ?? '')).resolves.toBeDefined()
      expect(await loadKeyState(dir)).toEqual(initial)

      survivingStage?.release()
      const results = await completed
      expect(results).toContainEqual({ status: 'fulfilled', value: undefined })
      const failure = results.find((result) => result.status === 'rejected')
      expect(failure?.reason).toBeInstanceOf(FilesystemError)
      expect(await loadKeyState(dir)).toEqual(next)
    } finally {
      renameBarrier.enabled = false
      for (const stage of renameBarrier.pending.splice(0)) stage.release()
      await completed
    }
  })
})

describe('grace-period expiry on load', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2024-01-15T10:00:00.000Z'))
  })
  afterEach(() => {
    vi.useRealTimers()
  })

  it('drops the previous key once the persisted grace period has elapsed', async () => {
    const snapshot: KeyStateSnapshot = {
      current: makeKey('k-2-bbbb', 0x22),
      previous: makeKey('k-1-aaaa', 0x11),
      gracePeriodExpiresAt: Date.now() + 5_000,
    }
    await saveKeyState(dir, snapshot)

    // Advance past the grace period, then load in the "next process".
    vi.setSystemTime(new Date('2024-01-15T10:00:06.000Z'))
    const loaded = await loadKeyState(dir)
    expect(loaded?.current.id).toBe('k-2-bbbb')
    expect(loaded?.previous).toBeUndefined()
    expect(loaded?.gracePeriodExpiresAt).toBeUndefined()
  })
})

describe('encryption at rest and file permissions', () => {
  it('writes the state as an iv:authTag:ciphertext envelope, not plaintext', async () => {
    const current = makeKey('k-secret-id', 0x33)
    await saveKeyState(dir, { current })

    const raw = await fs.readFile(path.join(dir, 'keys.enc'), 'utf8')
    // The key id and base64 key bytes must not appear in cleartext.
    expect(raw).not.toContain('k-secret-id')
    expect(raw).not.toContain(Buffer.from(current.key).toString('base64'))
    // Envelope shape: three base64 segments separated by colons.
    expect(raw.split(':')).toHaveLength(3)
  })

  it('writes the state file and wrapping key owner-only (0600)', async () => {
    // File-mode bits are POSIX-only; skip the assertion on Windows.
    if (process.platform === 'win32') return
    await saveKeyState(dir, { current: makeKey('k-1-aaaa', 0x11) })

    const stateMode = (await fs.stat(path.join(dir, 'keys.enc'))).mode & 0o777
    const wrapMode = (await fs.stat(path.join(dir, '.keys.wrap'))).mode & 0o777
    expect(stateMode).toBe(0o600)
    expect(wrapMode).toBe(0o600)
  })
})

describe('corrupt / tampered state degrades safely', () => {
  it('returns undefined for a non-envelope (garbage) state file', async () => {
    await saveKeyState(dir, { current: makeKey('k-1-aaaa', 0x11) })
    await fs.writeFile(path.join(dir, 'keys.enc'), 'not-an-envelope', 'utf8')
    expect(await loadKeyState(dir)).toBeUndefined()
  })

  it('returns undefined when the ciphertext fails authentication (tampered)', async () => {
    await saveKeyState(dir, { current: makeKey('k-1-aaaa', 0x11) })
    const statePath = path.join(dir, 'keys.enc')
    const envelope = await fs.readFile(statePath, 'utf8')
    const [iv, tag, ct] = envelope.split(':')
    // Flip the ciphertext so GCM authentication fails on decrypt.
    const tampered = Buffer.from(ct ?? '', 'base64')
    if (tampered.length > 0) tampered[0] ^= 0xff
    await fs.writeFile(statePath, `${iv ?? ''}:${tag ?? ''}:${tampered.toString('base64')}`, 'utf8')
    expect(await loadKeyState(dir)).toBeUndefined()
  })

  it('recovers from a corrupt (wrong-length) wrapping key by regenerating it', async () => {
    // First save establishes both keys.enc and a valid .keys.wrap.
    await saveKeyState(dir, { current: makeKey('k-old-aaaa', 0x11) })

    // Truncate the wrapping key to a non-32-byte length, as a partial write or
    // disk corruption would. The old state is now unrecoverable (load degrades
    // to "no state") — but a subsequent save must not throw "Invalid key
    // length"; it regenerates the wrap key and persists fresh state.
    const wrapPath = path.join(dir, '.keys.wrap')
    await fs.writeFile(wrapPath, Buffer.alloc(7, 0xab), { mode: 0o600 })

    // Load degrades gracefully rather than crashing.
    expect(await loadKeyState(dir)).toBeUndefined()

    // Save succeeds (no throw) and the freshly wrapped state round-trips.
    const fresh = makeKey('k-new-bbbb', 0x22)
    await saveKeyState(dir, { current: fresh })
    expect((await fs.stat(wrapPath)).size).toBe(32)
    const loaded = await loadKeyState(dir)
    expect(loaded?.current.id).toBe('k-new-bbbb')
  })
})

// Regression: issue #228. The first `store` persists key state before any
// secret is written, so `saveKeyState` is the code path that creates the config
// directory. When its parent is read-only, `fs.mkdir` fails with EACCES; that
// failure previously propagated as a raw Node error and the CLI leaked
// `EACCES: … mkdir '<path>'`. It must now surface as a typed FilesystemError
// (permission 'create', errno code preserved) so the CLI can render it cleanly.
describe('saveKeyState wraps a config-dir creation failure as a typed FilesystemError (issue #228)', () => {
  // chmod-500 only denies mkdir on POSIX, and not for root (which bypasses
  // permission bits) — mirror the CLI UAT guard.
  const canTestDirPermissions =
    process.platform !== 'win32' &&
    !(typeof process.getuid === 'function' && process.getuid() === 0)

  it.skipIf(!canTestDirPermissions)(
    'throws FilesystemError (not a raw EACCES) when the parent dir is read-only',
    async () => {
      const parent = path.join(dir, 'ro')
      await fs.mkdir(parent, { recursive: true })
      await fs.chmod(parent, 0o500)
      const target = path.join(parent, 'sub')

      try {
        await expect(saveKeyState(target, { current: makeKey('k-1-aaaa', 0x11) })).rejects.toEqual(
          expect.objectContaining({
            name: 'FilesystemError',
            path: target,
            permission: 'create',
            code: 'EACCES',
          }),
        )
      } finally {
        // Restore write permission so afterEach can remove the temp tree.
        await fs.chmod(parent, 0o755).catch(() => undefined)
      }
    },
  )
})
