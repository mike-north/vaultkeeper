/**
 * Integration tests for the VaultKeeper signing surface.
 *
 * Exercises the full flow against a real (file) signing backend:
 *   createSigningKey → exportPublicKey → authorizeSigningKey → sign → verify.
 *
 * The signature format is a detached-payload Compact JWS (RFC 7515 §7.2.2 +
 * RFC 7797 b64:false, crit:["b64"], alg EdDSA).
 *
 * @see https://www.rfc-editor.org/rfc/rfc7515
 * @see https://www.rfc-editor.org/rfc/rfc7797
 */

import * as fs from 'node:fs/promises'
import * as os from 'node:os'
import * as path from 'node:path'
import * as crypto from 'node:crypto'
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { decodeProtectedHeader, flattenedVerify } from 'jose'
import { VaultKeeper } from '../../src/index.js'
import { AuthorizationDeniedError } from '../../src/errors.js'
import { FileBackend } from '../../src/backend/file-backend.js'
import * as session from '../../src/identity/session.js'
import * as backendTypes from '../../src/backend/types.js'
import { BackendRegistry } from '../../src/backend/registry.js'

let storageDir: string

async function createVault(): Promise<VaultKeeper> {
  return VaultKeeper.init({ skipDoctor: true, backend: new FileBackend(storageDir) })
}

beforeEach(async () => {
  storageDir = await fs.mkdtemp(path.join(os.tmpdir(), 'vk-vault-sign-'))
})

afterEach(async () => {
  vi.restoreAllMocks()
  await fs.rm(storageDir, { recursive: true, force: true })
})

describe('VaultKeeper signing integration', () => {
  it('full flow: create → export → sign → static verify', async () => {
    const vault = await createVault()
    const created = await vault.createSigningKey('approval', 'EdDSA')
    expect(created.algorithm).toBe('EdDSA')

    const pub = await vault.exportPublicKey('approval')
    expect(pub.publicKeyPem).toContain('-----BEGIN PUBLIC KEY-----')
    expect(pub.kid).toBe(created.kid)

    const payload = 'gate1:abc123:1706000000'
    const token = await vault.authorizeSigningKey('approval')
    const { result } = await vault.sign(token, { payload })

    // Detached compact JWS: <protected>..<signature> with empty payload segment.
    expect(result.jws.split('.')).toHaveLength(3)
    expect(result.jws.split('.')[1]).toBe('')

    await expect(
      VaultKeeper.verify({ payload, jws: result.jws, publicKey: pub.publicKeyPem }),
    ).resolves.toBe(true)
  })

  it("rejects another vault's signing capability before invoking either backend", async () => {
    const otherStorageDir = await fs.mkdtemp(path.join(os.tmpdir(), 'vk-vault-sign-other-'))
    try {
      const firstBackend = new FileBackend(storageDir)
      const secondBackend = new FileBackend(otherStorageDir)
      const firstVault = await VaultKeeper.init({ skipDoctor: true, backend: firstBackend })
      const secondVault = await VaultKeeper.init({ skipDoctor: true, backend: secondBackend })
      await firstVault.createSigningKey('overlapping', 'EdDSA')
      await secondVault.createSigningKey('overlapping', 'EdDSA')
      const firstPublicKey = await firstVault.exportPublicKey('overlapping')
      const secondPublicKey = await secondVault.exportPublicKey('overlapping')
      expect(firstPublicKey.kid).not.toBe(secondPublicKey.kid)
      const firstToken = await firstVault.authorizeSigningKey('overlapping')
      const secondToken = await secondVault.authorizeSigningKey('overlapping')
      const firstSign = vi.spyOn(firstBackend, 'signWithKey')
      const secondSign = vi.spyOn(secondBackend, 'signWithKey')
      const presenceProbe = vi.spyOn(backendTypes, 'getBackendCapabilities')
      const denial = new AuthorizationDeniedError(
        'Capability token was issued by another vault instance',
      )
      const attempts = await Promise.allSettled([
        secondVault.sign(firstToken, { payload: 'wrong vault' }),
        firstVault.sign(secondToken, { payload: 'wrong vault' }, { requirePresencePerUse: true }),
      ])
      for (const attempt of attempts) {
        expect(attempt).toMatchObject({ status: 'rejected', reason: denial })
        if (attempt.status === 'rejected') {
          expect(attempt.reason).toBeInstanceOf(AuthorizationDeniedError)
        }
      }
      expect(firstSign).not.toHaveBeenCalled()
      expect(secondSign).not.toHaveBeenCalled()
      expect(presenceProbe).not.toHaveBeenCalled()

      const payload = 'right vault'
      for (const { vault, token, publicKey } of [
        { vault: firstVault, token: firstToken, publicKey: firstPublicKey },
        { vault: secondVault, token: secondToken, publicKey: secondPublicKey },
      ]) {
        const { result } = await vault.sign(token, { payload })
        expect(decodeProtectedHeader(result.jws).kid).toBe(publicKey.kid)
        await expect(
          VaultKeeper.verify({ payload, jws: result.jws, publicKey: publicKey.publicKeyPem }),
        ).resolves.toBe(true)
      }
      expect(firstSign).toHaveBeenCalledExactlyOnceWith(
        'signing-key:overlapping',
        expect.any(Uint8Array),
      )
      expect(secondSign).toHaveBeenCalledExactlyOnceWith(
        'signing-key:overlapping',
        expect.any(Uint8Array),
      )
    } finally {
      await fs.rm(otherStorageDir, { recursive: true, force: true })
    }
  })

  it('rejects a foreign signing capability before resolving an unopened backend', async () => {
    const issuer = await createVault()
    await issuer.createSigningKey('approval', 'EdDSA')
    const token = await issuer.authorizeSigningKey('approval')
    const receiver = await VaultKeeper.init({
      skipDoctor: true,
      config: {
        version: 1,
        backends: [{ type: 'file', enabled: true, path: storageDir }],
        keyRotation: { gracePeriodDays: 7 },
        defaults: { ttlMinutes: 60, trustTier: 3 },
      },
    })
    const createBackend = vi.spyOn(BackendRegistry, 'create')

    await expect(receiver.sign(token, { payload: 'wrong vault' })).rejects.toThrow(
      new AuthorizationDeniedError('Capability token was issued by another vault instance'),
    )
    expect(createBackend).not.toHaveBeenCalled()
  })

  it('verify rejects a tampered payload (returns false)', async () => {
    const vault = await createVault()
    await vault.createSigningKey('approval', 'EdDSA')
    const pub = await vault.exportPublicKey('approval')
    const token = await vault.authorizeSigningKey('approval')
    const { result } = await vault.sign(token, { payload: 'original' })

    await expect(
      VaultKeeper.verify({ payload: 'tampered', jws: result.jws, publicKey: pub.publicKeyPem }),
    ).resolves.toBe(false)
  })

  // AC5: third-party verifiability — a generic JOSE flattenedVerify path that
  // does not use vaultkeeper's own verify implementation accepts the signature.
  it('sign output verifies with a generic JOSE library path', async () => {
    const vault = await createVault()
    await vault.createSigningKey('approval', 'EdDSA')
    const pub = await vault.exportPublicKey('approval')
    const token = await vault.authorizeSigningKey('approval')
    const payload = Buffer.from('third-party', 'utf8')
    const { result } = await vault.sign(token, { payload })

    const [protectedB64, , signature] = result.jws.split('.')
    const verified = await flattenedVerify(
      { protected: protectedB64 ?? '', payload, signature: signature ?? '' },
      crypto.createPublicKey(pub.publicKeyPem),
    )
    expect(Buffer.from(verified.payload).toString('utf8')).toBe('third-party')
  })

  // AC3: the signing capability token carries no key material — only kid,
  // backendRef, and the keyType discriminator.
  it('signing token claims contain no key material', async () => {
    const vault = await createVault()
    await vault.createSigningKey('approval', 'EdDSA')
    const mintToken = vi.spyOn(session, 'createSigningCapabilityToken')
    const token = await vault.authorizeSigningKey('approval')
    const owner = mintToken.mock.lastCall?.[1]
    const claims = owner === undefined ? undefined : session.validateCapabilityToken(token, owner)
    const { kid } = await vault.exportPublicKey('approval')
    expect(claims).toStrictEqual({
      backendRef: 'signing-key:approval',
      keyType: 'signing-key',
      kid,
    })
  })

  // Defense in depth: a signing-key token must be rejected by every
  // secret-access path.
  it('getSecret/fetch/exec reject a signing-key token', async () => {
    const vault = await createVault()
    await vault.createSigningKey('approval', 'EdDSA')
    const token = await vault.authorizeSigningKey('approval')

    expect(() => vault.getSecret(token)).toThrow(AuthorizationDeniedError)
    await expect(vault.fetch(token, { url: 'https://example.com' })).rejects.toBeInstanceOf(
      AuthorizationDeniedError,
    )
    await expect(vault.exec(token, { command: 'echo' })).rejects.toBeInstanceOf(
      AuthorizationDeniedError,
    )
  })

  it('returns vaultResponse with keyStatus current', async () => {
    const vault = await createVault()
    await vault.createSigningKey('approval', 'EdDSA')
    const token = await vault.authorizeSigningKey('approval')
    const { vaultResponse } = await vault.sign(token, { payload: 'x' })
    expect(vaultResponse.keyStatus).toBe('current')
  })
})
