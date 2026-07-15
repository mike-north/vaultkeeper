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
import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { flattenedVerify } from 'jose'
import { VaultKeeper } from '../../src/index.js'
import { AuthorizationDeniedError } from '../../src/errors.js'
import { FileBackend } from '../../src/backend/file-backend.js'
import { validateCapabilityToken, isSigningClaims } from '../../src/identity/session.js'

let storageDir: string

async function createVault(): Promise<VaultKeeper> {
  return VaultKeeper.init({ skipDoctor: true, backend: new FileBackend(storageDir) })
}

beforeEach(async () => {
  storageDir = await fs.mkdtemp(path.join(os.tmpdir(), 'vk-vault-sign-'))
})

afterEach(async () => {
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
    const token = await vault.authorizeSigningKey('approval')

    const claims = validateCapabilityToken(token)
    expect(isSigningClaims(claims)).toBe(true)
    expect(Object.keys(claims).sort()).toEqual(['backendRef', 'keyType', 'kid'])
    // No secret/private-key fields anywhere in the claims.
    expect('val' in claims).toBe(false)
    const serialized = JSON.stringify(claims)
    expect(serialized).not.toContain('PRIVATE KEY')
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
