/**
 * Unit tests for the detached-payload Compact JWS assembly and verification.
 *
 * The signature contract is a detached-payload Compact JWS: RFC 7515 §7.2.2
 * plus the RFC 7797 unencoded-payload option (`b64:false`, `crit:["b64"]`),
 * `alg:EdDSA`.
 *
 * @see https://www.rfc-editor.org/rfc/rfc7515 (JWS)
 * @see https://www.rfc-editor.org/rfc/rfc7797 (Unencoded Payload Option)
 */

import * as crypto from 'node:crypto'
import { describe, it, expect } from 'vitest'
import { CompactSign, flattenedVerify } from 'jose'
import { createDetachedJws, verifyDetachedJws } from '../../../src/access/jws.js'
import { InvalidKeyMaterialError } from '../../../src/errors.js'

function makeEd25519(): {
  privateKey: crypto.KeyObject
  publicKeyPem: string
} {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519')
  return {
    privateKey,
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
  }
}

/** A backend-style signer: raw Ed25519 signature over the given bytes. */
function edSigner(privateKey: crypto.KeyObject): (data: Buffer) => Promise<Buffer> {
  return (data: Buffer) => Promise.resolve(crypto.sign(null, data, privateKey))
}

const KID = 'test-kid'

describe('createDetachedJws', () => {
  it('produces the detached compact form <protected>..<signature>', async () => {
    const { privateKey } = makeEd25519()
    const jws = await createDetachedJws(KID, 'hello', edSigner(privateKey))
    const parts = jws.split('.')
    // RFC 7515 §7.2.2 detached: three parts, empty middle (payload) segment.
    expect(parts).toHaveLength(3)
    expect(parts[1]).toBe('')
  })

  it('sets the documented protected header (alg EdDSA, b64:false, crit:["b64"], kid)', async () => {
    const { privateKey } = makeEd25519()
    const jws = await createDetachedJws(KID, 'hello', edSigner(privateKey))
    const header: unknown = JSON.parse(
      Buffer.from(jws.split('.')[0] ?? '', 'base64url').toString('utf8'),
    )
    expect(header).toEqual({ alg: 'EdDSA', b64: false, crit: ['b64'], kid: KID })
  })

  it('is byte-identical to jose CompactSign for the same header and payload', async () => {
    const { privateKey } = makeEd25519()
    const payload = Buffer.from('payload.with.dots\nand newline', 'utf8')
    const ours = await createDetachedJws(KID, payload, edSigner(privateKey))
    const jose = await new CompactSign(payload)
      .setProtectedHeader({ alg: 'EdDSA', b64: false, crit: ['b64'], kid: KID })
      .sign(privateKey)
    expect(ours).toBe(jose)
  })

  // AC5: the documented format alone suffices — a generic JOSE verify path
  // (jose flattenedVerify) that never touches vaultkeeper's verify succeeds.
  it('output verifies with a third-party JOSE flattenedVerify path', async () => {
    const { privateKey, publicKeyPem } = makeEd25519()
    const payload = Buffer.from('third-party-check', 'utf8')
    const jws = await createDetachedJws(KID, payload, edSigner(privateKey))
    const [protectedB64, , signature] = jws.split('.')
    const result = await flattenedVerify(
      { protected: protectedB64 ?? '', payload, signature: signature ?? '' },
      crypto.createPublicKey(publicKeyPem),
    )
    expect(Buffer.from(result.payload).toString('utf8')).toBe('third-party-check')
  })
})

describe('verifyDetachedJws', () => {
  it('returns true for a valid signature over the same payload', async () => {
    const { privateKey, publicKeyPem } = makeEd25519()
    const jws = await createDetachedJws(KID, 'the-payload', edSigner(privateKey))
    await expect(
      verifyDetachedJws({ payload: 'the-payload', jws, publicKey: publicKeyPem }),
    ).resolves.toBe(true)
  })

  it('returns false for a tampered payload', async () => {
    const { privateKey, publicKeyPem } = makeEd25519()
    const jws = await createDetachedJws(KID, 'the-payload', edSigner(privateKey))
    await expect(
      verifyDetachedJws({ payload: 'the-payload-x', jws, publicKey: publicKeyPem }),
    ).resolves.toBe(false)
  })

  it('returns false for the wrong public key', async () => {
    const { privateKey } = makeEd25519()
    const other = makeEd25519()
    const jws = await createDetachedJws(KID, 'p', edSigner(privateKey))
    await expect(
      verifyDetachedJws({ payload: 'p', jws, publicKey: other.publicKeyPem }),
    ).resolves.toBe(false)
  })

  it('returns false for a JWS with the wrong number of segments', async () => {
    const { publicKeyPem } = makeEd25519()
    await expect(
      verifyDetachedJws({ payload: 'p', jws: 'a.b', publicKey: publicKeyPem }),
    ).resolves.toBe(false)
  })

  it('returns false for a non-detached JWS (non-empty payload segment)', async () => {
    const { privateKey, publicKeyPem } = makeEd25519()
    const jws = await createDetachedJws(KID, 'p', edSigner(privateKey))
    const [protectedB64, , signature] = jws.split('.')
    const nonDetached = `${protectedB64 ?? ''}.cGF5bG9hZA.${signature ?? ''}`
    await expect(
      verifyDetachedJws({ payload: 'p', jws: nonDetached, publicKey: publicKeyPem }),
    ).resolves.toBe(false)
  })

  it('returns false for a header with a disallowed alg', async () => {
    const { publicKeyPem } = makeEd25519()
    // Hand-build a header claiming HS256 (not EdDSA); signature is irrelevant
    // because header validation rejects it before verification.
    const header = Buffer.from(
      JSON.stringify({ alg: 'HS256', b64: false, crit: ['b64'] }),
    ).toString('base64url')
    await expect(
      verifyDetachedJws({ payload: 'p', jws: `${header}..AAAA`, publicKey: publicKeyPem }),
    ).resolves.toBe(false)
  })

  it('throws InvalidKeyMaterialError for an unparseable public key', async () => {
    const { privateKey } = makeEd25519()
    const jws = await createDetachedJws(KID, 'p', edSigner(privateKey))
    await expect(
      verifyDetachedJws({ payload: 'p', jws, publicKey: 'not-a-pem' }),
    ).rejects.toBeInstanceOf(InvalidKeyMaterialError)
  })

  it('throws InvalidKeyMaterialError when a private key is supplied as public', async () => {
    const { privateKey } = makeEd25519()
    const jws = await createDetachedJws(KID, 'p', edSigner(privateKey))
    const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString()
    await expect(
      verifyDetachedJws({ payload: 'p', jws, publicKey: privatePem }),
    ).rejects.toBeInstanceOf(InvalidKeyMaterialError)
  })

  // The documented contract is an SPKI PEM public key. A non-SPKI encoding must
  // be rejected as a typed operational fault, not silently accepted — otherwise
  // the documented third-party-verify contract is weaker than it claims.
  it('throws InvalidKeyMaterialError for a PKCS#1 (non-SPKI) public key', async () => {
    const { privateKey } = makeEd25519()
    const jws = await createDetachedJws(KID, 'p', edSigner(privateKey))
    const rsa = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 })
    const pkcs1Pem = rsa.publicKey.export({ type: 'pkcs1', format: 'pem' }).toString()
    expect(pkcs1Pem).toContain('BEGIN RSA PUBLIC KEY')
    await expect(
      verifyDetachedJws({ payload: 'p', jws, publicKey: pkcs1Pem }),
    ).rejects.toBeInstanceOf(InvalidKeyMaterialError)
  })

  it('throws InvalidKeyMaterialError for a valid SPKI key of the wrong type (RSA)', async () => {
    const { privateKey } = makeEd25519()
    const jws = await createDetachedJws(KID, 'p', edSigner(privateKey))
    const rsa = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 })
    const rsaSpkiPem = rsa.publicKey.export({ type: 'spki', format: 'pem' }).toString()
    expect(rsaSpkiPem).toContain('BEGIN PUBLIC KEY')
    await expect(
      verifyDetachedJws({ payload: 'p', jws, publicKey: rsaSpkiPem }),
    ).rejects.toBeInstanceOf(InvalidKeyMaterialError)
  })
})
