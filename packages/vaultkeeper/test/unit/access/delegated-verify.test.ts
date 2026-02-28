/**
 * Tests for delegatedVerify — the verification utility.
 *
 * @see https://nodejs.org/api/crypto.html#cryptoverifyalgorithm-data-key-signature-callback
 */

import * as crypto from 'node:crypto'
import { describe, it, expect, beforeAll } from 'vitest'
import { delegatedVerify } from '../../../src/access/delegated-verify.js'
import { InvalidAlgorithmError } from '../../../src/errors.js'

let ed25519Private: string
let ed25519Public: string
let rsaPrivate: string
let rsaPublic: string

beforeAll(() => {
  const ed = crypto.generateKeyPairSync('ed25519')
  ed25519Private = ed.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString()
  ed25519Public = ed.publicKey.export({ type: 'spki', format: 'pem' }).toString()

  const rsa = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 })
  rsaPrivate = rsa.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString()
  rsaPublic = rsa.publicKey.export({ type: 'spki', format: 'pem' }).toString()
})

function signEd25519(data: string): string {
  return crypto
    .sign(null, Buffer.from(data), crypto.createPrivateKey(ed25519Private))
    .toString('base64')
}

function signRsa(data: string, algorithm = 'sha256'): string {
  return crypto
    .sign(algorithm, Buffer.from(data), crypto.createPrivateKey(rsaPrivate))
    .toString('base64')
}

describe('delegatedVerify', () => {
  describe('Ed25519 valid signatures', () => {
    it('returns true for a valid Ed25519 signature', () => {
      const data = 'hello world'
      const signature = signEd25519(data)

      expect(delegatedVerify({ data, signature, publicKey: ed25519Public })).toBe(true)
    })
  })

  describe('RSA valid signatures', () => {
    it('returns true for a valid RSA sha256 signature', () => {
      const data = 'rsa test'
      const signature = signRsa(data)

      expect(delegatedVerify({ data, signature, publicKey: rsaPublic })).toBe(true)
    })

    it('returns true with algorithm override (sha512)', () => {
      const data = 'rsa sha512'
      const signature = signRsa(data, 'sha512')

      expect(
        delegatedVerify({ data, signature, publicKey: rsaPublic, algorithm: 'sha512' }),
      ).toBe(true)
    })

    it('returns false when algorithm override does not match signing algorithm', () => {
      const data = 'mismatch'
      const signature = signRsa(data, 'sha256')

      expect(
        delegatedVerify({ data, signature, publicKey: rsaPublic, algorithm: 'sha512' }),
      ).toBe(false)
    })
  })

  describe('invalid signatures', () => {
    it('returns false for tampered data', () => {
      const signature = signEd25519('original')

      expect(
        delegatedVerify({ data: 'tampered', signature, publicKey: ed25519Public }),
      ).toBe(false)
    })

    it('returns false for wrong key', () => {
      const otherEd = crypto.generateKeyPairSync('ed25519')
      const otherPublic = otherEd.publicKey.export({ type: 'spki', format: 'pem' }).toString()
      const signature = signEd25519('data')

      expect(
        delegatedVerify({ data: 'data', signature, publicKey: otherPublic }),
      ).toBe(false)
    })

    it('returns false for invalid signature format', () => {
      expect(
        delegatedVerify({
          data: 'data',
          signature: 'not-valid-base64!!!',
          publicKey: ed25519Public,
        }),
      ).toBe(false)
    })

    it('returns false for invalid public key', () => {
      expect(
        delegatedVerify({ data: 'data', signature: 'AAAA', publicKey: 'not-a-pem' }),
      ).toBe(false)
    })

    it('throws InvalidAlgorithmError for weak algorithm (md5)', () => {
      const data = 'test'
      const signature = signRsa(data)

      expect(() =>
        delegatedVerify({ data, signature, publicKey: rsaPublic, algorithm: 'md5' }),
      ).toThrow(InvalidAlgorithmError)
    })

    it('throws InvalidAlgorithmError for weak algorithm (sha1)', () => {
      const data = 'test'
      const signature = signRsa(data)

      expect(() =>
        delegatedVerify({ data, signature, publicKey: rsaPublic, algorithm: 'sha1' }),
      ).toThrow(InvalidAlgorithmError)
    })
  })

  describe('private key rejection', () => {
    it('returns false when a private key PEM is passed as publicKey', () => {
      const data = 'test'
      const signature = signEd25519(data)

      expect(
        delegatedVerify({ data, signature, publicKey: ed25519Private }),
      ).toBe(false)
    })

    it('returns false when an RSA private key PEM is passed as publicKey', () => {
      const data = 'test'
      const signature = signRsa(data)

      expect(
        delegatedVerify({ data, signature, publicKey: rsaPrivate }),
      ).toBe(false)
    })
  })

  describe('algorithm case normalization', () => {
    it('accepts uppercase algorithm names', () => {
      const data = 'case test'
      const signature = signRsa(data, 'sha256')

      expect(
        delegatedVerify({ data, signature, publicKey: rsaPublic, algorithm: 'SHA256' }),
      ).toBe(true)
    })

    it('accepts mixed-case algorithm names', () => {
      const data = 'case test'
      const signature = signRsa(data, 'sha512')

      expect(
        delegatedVerify({ data, signature, publicKey: rsaPublic, algorithm: 'Sha512' }),
      ).toBe(true)
    })
  })

  describe('edge cases', () => {
    it('verifies signature over empty string', () => {
      const data = ''
      const signature = signEd25519(data)

      expect(delegatedVerify({ data, signature, publicKey: ed25519Public })).toBe(true)
    })

    it('verifies signature over empty Buffer', () => {
      const data = Buffer.alloc(0)
      const signature = crypto
        .sign(null, data, crypto.createPrivateKey(ed25519Private))
        .toString('base64')

      expect(delegatedVerify({ data, signature, publicKey: ed25519Public })).toBe(true)
    })
  })
})
