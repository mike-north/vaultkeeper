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
import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import * as fs from 'node:fs/promises'
import * as os from 'node:os'
import * as path from 'node:path'
import { VaultKeeper } from '../../src/vault.js'
import { registerBuiltinBackends } from '../../src/backend/register-builtins.js'
import { KeyRevokedError, RotationInProgressError } from '../../src/errors.js'

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
