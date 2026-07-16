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
import { loadKeyState, saveKeyState } from '../../../src/keys/storage.js'
import type { KeyMaterial, KeyStateSnapshot } from '../../../src/keys/types.js'

const CREATED_AT = new Date('2024-01-15T10:30:00.000Z')

function makeKey(id: string, byte: number): KeyMaterial {
  return { id, key: new Uint8Array(32).fill(byte), createdAt: CREATED_AT }
}

let dir: string

beforeEach(async () => {
  dir = await fs.mkdtemp(path.join(os.tmpdir(), 'vk-keystore-'))
})

afterEach(async () => {
  await fs.rm(dir, { recursive: true, force: true })
})

describe('saveKeyState / loadKeyState round-trip', () => {
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
