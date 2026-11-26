/**
 * Integration tests for cross-process key persistence (issue #59).
 *
 * Each `VaultKeeper.init({ configDir })` below models a separate CLI process:
 * it loads its configuration from the shared config directory (no injected
 * `config`/`backend`), so key material is persisted to and reloaded from disk.
 * A token minted by one instance must authorize in a later instance, the
 * rotation grace-period guard must survive across instances, and a revoked key
 * must surface `KeyRevokedError` — not a generic failure.
 *
 * Uses the real Node crypto file backend under isolated temp directories; dev
 * mode is used for identity so no trust manifest or real executable is needed.
 *
 * @see https://github.com/mike-north/vaultkeeper/issues/59
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import * as fs from 'node:fs/promises'
import * as os from 'node:os'
import * as path from 'node:path'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { fileURLToPath } from 'node:url'
import { VaultKeeper } from '../../src/vault.js'
import { registerBuiltinBackends } from '../../src/backend/register-builtins.js'
import { DecryptionError, KeyRevokedError, RotationInProgressError } from '../../src/errors.js'
import { publishFile } from '../../src/util/publish-file.js'

vi.mock('node:fs/promises', async (original) => ({
  ...(await original<typeof fs>()),
}))
vi.mock('node:os', async (original) => ({ ...(await original<typeof os>()) }))

/** Hold both operations after the real filesystem reports absence. */
async function overlapMissingReads(paths: string[]): Promise<void> {
  const real = await vi.importActual<typeof fs>('node:fs/promises')
  const gates = new Map(
    paths.map((file) => {
      let release: () => void = () => undefined
      const promise = new Promise<void>((resolve) => {
        release = resolve
      })
      return [file, { promise, release, seen: 0 }]
    }),
  )
  vi.spyOn(fs, 'readFile').mockImplementation(async (file, options) => {
    try {
      return await real.readFile(file, options)
    } catch (err) {
      const gate = typeof file === 'string' ? gates.get(file) : undefined
      if (gate !== undefined && err instanceof Error && 'code' in err && err.code === 'ENOENT') {
        gate.seen++
        if (gate.seen === 2) gate.release()
        await gate.promise
      }
      throw err
    }
  })
}

const SECRET_NAME = 'API_KEY'
const SECRET_VALUE = 's3cr3t-value'

let configDir = ''
let secretsDir = ''

async function writeConfig(gracePeriodDays: number): Promise<void> {
  const config = {
    version: 1,
    backends: [{ type: 'file', enabled: true, path: secretsDir }],
    keyRotation: { gracePeriodDays },
    defaults: { ttlMinutes: 60, trustTier: 3 },
    developmentMode: { executables: ['dev'] },
  }
  await fs.writeFile(path.join(configDir, 'config.json'), JSON.stringify(config), {
    mode: 0o600,
  })
}

/** A fresh vault built from the shared config dir — models a new process. */
function newProcess(): Promise<VaultKeeper> {
  return VaultKeeper.init({ skipDoctor: true, configDir })
}

beforeEach(async () => {
  registerBuiltinBackends()
  configDir = await fs.mkdtemp(path.join(os.tmpdir(), 'vk-persist-cfg-'))
  secretsDir = await fs.mkdtemp(path.join(os.tmpdir(), 'vk-persist-secrets-'))
  await writeConfig(7)
})

afterEach(async () => {
  vi.restoreAllMocks()
  await fs.rm(configDir, { recursive: true, force: true })
  await fs.rm(secretsDir, { recursive: true, force: true })
})

describe('cross-process token reuse (criterion 2)', () => {
  it('authorizes a token minted by an earlier instance in a later instance', async () => {
    const minter = await newProcess()
    await minter.store(SECRET_NAME, SECRET_VALUE)
    const jwe = await minter.setup(SECRET_NAME, { skipTrust: true })

    // A brand-new instance (fresh KeyManager) reloads the persisted keys.
    const authorizer = await newProcess()
    const { token, vaultResponse } = await authorizer.authorize(jwe)
    expect(vaultResponse.keyStatus).toBe('current')

    let secret: string | undefined
    authorizer.getSecret(token).read((buf) => {
      secret = buf.toString('utf8')
    })
    expect(secret).toBe(SECRET_VALUE)
  })

  it('persists a keys.enc file under the config dir', async () => {
    await newProcess()
    const entries = await fs.readdir(configDir)
    expect(entries).toContain('keys.enc')
  })
})

describe('cross-process rotation guard (criterion 5)', () => {
  it('rejects a second rotation while the previous rotation is still in grace', async () => {
    const first = await newProcess()
    await first.rotateKey()

    // A separate instance sees the persisted grace period and refuses to rotate.
    const second = await newProcess()
    await expect(second.rotateKey()).rejects.toBeInstanceOf(RotationInProgressError)
  })
})

describe('revoked-key error accuracy (criterion 4)', () => {
  it('surfaces KeyRevokedError when authorizing a token whose key was revoked', async () => {
    const minter = await newProcess()
    await minter.store(SECRET_NAME, SECRET_VALUE)
    const jwe = await minter.setup(SECRET_NAME, { skipTrust: true })

    // Revoke in a second process: the minting key is discarded and replaced.
    const revoker = await newProcess()
    await revoker.revokeKey()

    // A third process cannot resolve the revoked kid — the error is specific.
    const authorizer = await newProcess()
    await expect(authorizer.authorize(jwe)).rejects.toBeInstanceOf(KeyRevokedError)
  })
})

describe('overlapping first use', () => {
  it('does not change POSIX permissions on Windows', async () => {
    vi.spyOn(os, 'platform').mockReturnValue('win32')
    const real = await vi.importActual<typeof fs>('node:fs/promises')
    let chmodCalled = false
    vi.spyOn(fs, 'open').mockImplementation(async (...args) => {
      const handle = await real.open(...args)
      vi.spyOn(handle, 'chmod').mockImplementation(() => {
        chmodCalled = true
        return Promise.resolve()
      })
      return handle
    })
    await publishFile(path.join(configDir, 'test-file'), 'content', 'test file')
    expect(chmodCalled).toBe(false)
  })
  it.skipIf(process.platform === 'win32')('reopens owner-readable files under a restrictive umask', async () => {
    await fs.mkdir(path.join(configDir, 'file'))
    await fs.writeFile(path.join(configDir, 'config.json'), JSON.stringify({
      version: 1,
      backends: [{ type: 'file', enabled: true, path: path.join(configDir, 'file') }],
      keyRotation: { gracePeriodDays: 7 },
      defaults: { ttlMinutes: 60, trustTier: 3 },
    }))
    const fixture = fileURLToPath(new URL('../../scripts/restrictive-umask-test.mjs', import.meta.url))
    await promisify(execFile)(process.execPath, [fixture, configDir])
  })
  it.skipIf(process.platform === 'win32')('preserves a dangling state symlink without creating a wrapping key', async () => {
    const state = path.join(configDir, 'keys.enc')
    await fs.symlink('missing-target', state)
    await expect(newProcess()).rejects.toMatchObject({ name: 'FilesystemError' })
    expect(await fs.readlink(state)).toBe('missing-target')
    await expect(fs.lstat(path.join(configDir, '.keys.wrap'))).rejects.toMatchObject({ code: 'ENOENT' })
  })

  it('adopts state published between a missing read and the existence probe', async () => {
    await newProcess()
    const state = path.join(configDir, 'keys.enc')
    const real = await vi.importActual<typeof fs>('node:fs/promises')
    let missed = false
    vi.spyOn(fs, 'readFile').mockImplementation(async (file, options) => {
      if (file === state && !missed) {
        missed = true
        const error = new Error('simulated missing read')
        Object.assign(error, { code: 'ENOENT' })
        throw error
      }
      return real.readFile(file, options)
    })
    await expect(newProcess()).resolves.toBeInstanceOf(VaultKeeper)
    expect(missed).toBe(true)
  })
  it('reopens both records and authorizes both tokens after concurrent first writes', async () => {
    await overlapMissingReads([
      path.join(configDir, 'keys.enc'),
      path.join(configDir, '.keys.wrap'),
      path.join(secretsDir, '.key'),
    ])
    const [first, second] = await Promise.all([newProcess(), newProcess()])
    const records = ['first', 'second']
    const tokens = await Promise.all(
      [first, second].map(async (vault, index) => {
        const id = records[index] ?? 'unexpected'
        await vault.store(id, id)
        return vault.setup(id, { skipTrust: true })
      }),
    )

    const reopened = await newProcess()
    for (const [index, jwe] of tokens.entries()) {
      const { token } = await reopened.authorize(jwe)
      reopened.getSecret(token).read((secret) => {
        expect(secret.toString('utf8')).toBe(records[index])
      })
    }
  })

  it('reopens both successful file records after concurrent master-key creation', async () => {
    const first = await newProcess()
    const second = await newProcess()
    await overlapMissingReads([path.join(secretsDir, '.key')])
    await Promise.all([first.store('first', 'one'), second.store('second', 'two')])

    const reopened = await newProcess()
    const records: [string, string][] = [
      ['first', 'one'],
      ['second', 'two'],
    ]
    for (const [id, value] of records) {
      const { token } = await reopened.authorize(await reopened.setup(id, { skipTrust: true }))
      reopened.getSecret(token).read((secret) => {
        expect(secret.toString('utf8')).toBe(value)
      })
    }
  })

  it('cleans up staging after publication fails and allows a fresh retry', async () => {
    vi.spyOn(fs, 'link').mockRejectedValueOnce(
      new DecryptionError('Injected publication failure', configDir),
    )
    await expect(newProcess()).rejects.toMatchObject({ name: 'FilesystemError' })
    expect(await fs.readdir(configDir)).toEqual(['config.json'])
    await newProcess()
    expect((await fs.readdir(configDir)).sort()).toEqual(['.keys.wrap', 'config.json', 'keys.enc'])
  })

  it('does not recreate a missing master key when reading a record', async () => {
    const vault = await newProcess()
    await vault.store(SECRET_NAME, SECRET_VALUE)
    const master = path.join(secretsDir, '.key')
    await fs.unlink(master)

    await expect(vault.setup(SECRET_NAME, { skipTrust: true })).rejects.toThrow(DecryptionError)
    await expect(fs.stat(master)).rejects.toMatchObject({ code: 'ENOENT' })
  })

  it('does not recreate a missing wrapping key when opening persisted token state', async () => {
    await newProcess()
    const wrap = path.join(configDir, '.keys.wrap')
    await fs.unlink(wrap)

    await expect(newProcess()).rejects.toThrow(DecryptionError)
    await expect(fs.stat(wrap)).rejects.toMatchObject({ code: 'ENOENT' })
  })
})
