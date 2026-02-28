/**
 * Tests for delegatedSign — the signing access pattern.
 *
 * @see https://nodejs.org/api/crypto.html#cryptosignalgorithm-data-key-callback
 */

import * as crypto from 'node:crypto'
import { describe, it, expect, beforeAll } from 'vitest'
import { delegatedSign } from '../../../src/access/delegated-sign.js'

// Hoist key generation to avoid regenerating on every test (RSA is slow).
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

describe('delegatedSign', () => {
  describe('Ed25519 keys', () => {
    it('produces a verifiable signature for string data', () => {
      const data = 'hello world'
      const result = delegatedSign(ed25519Private, { data })

      expect(result.algorithm).toBe('ed25519')
      expect(result.signature).toBeTruthy()

      const valid = crypto.verify(
        null,
        Buffer.from(data),
        crypto.createPublicKey(ed25519Public),
        Buffer.from(result.signature, 'base64'),
      )
      expect(valid).toBe(true)
    })

    it('produces a verifiable signature for Buffer data', () => {
      const data = Buffer.from('binary payload')
      const result = delegatedSign(ed25519Private, { data })

      const valid = crypto.verify(
        null,
        data,
        crypto.createPublicKey(ed25519Public),
        Buffer.from(result.signature, 'base64'),
      )
      expect(valid).toBe(true)
    })

    it('ignores algorithm override for Ed25519', () => {
      const result = delegatedSign(ed25519Private, {
        data: 'test',
        algorithm: 'sha512',
      })
      expect(result.algorithm).toBe('ed25519')
    })
  })

  describe('RSA keys', () => {
    it('defaults to sha256 algorithm', () => {
      const data = 'rsa test'
      const result = delegatedSign(rsaPrivate, { data })

      expect(result.algorithm).toBe('sha256')

      const valid = crypto.verify(
        'sha256',
        Buffer.from(data),
        crypto.createPublicKey(rsaPublic),
        Buffer.from(result.signature, 'base64'),
      )
      expect(valid).toBe(true)
    })

    it('respects algorithm override', () => {
      const data = 'rsa sha512'
      const result = delegatedSign(rsaPrivate, { data, algorithm: 'sha512' })

      expect(result.algorithm).toBe('sha512')

      const valid = crypto.verify(
        'sha512',
        Buffer.from(data),
        crypto.createPublicKey(rsaPublic),
        Buffer.from(result.signature, 'base64'),
      )
      expect(valid).toBe(true)
    })
  })

  describe('negative cases', () => {
    it('throws on invalid PEM', () => {
      expect(() =>
        delegatedSign('not-a-pem', { data: 'test' }),
      ).toThrow()
    })

    it('throws when given a public key PEM instead of private', () => {
      expect(() =>
        delegatedSign(ed25519Public, { data: 'test' }),
      ).toThrow()
    })

    it('produces different signatures for different data', () => {
      const r1 = delegatedSign(ed25519Private, { data: 'a' })
      const r2 = delegatedSign(ed25519Private, { data: 'b' })
      expect(r1.signature).not.toBe(r2.signature)
    })

    it('throws for weak algorithm (md5)', () => {
      expect(() =>
        delegatedSign(rsaPrivate, { data: 'test', algorithm: 'md5' }),
      ).toThrow(/Unsupported signing algorithm/)
    })

    it('throws for weak algorithm (sha1)', () => {
      expect(() =>
        delegatedSign(rsaPrivate, { data: 'test', algorithm: 'sha1' }),
      ).toThrow(/Unsupported signing algorithm/)
    })
  })

  describe('edge cases', () => {
    it('signs empty string data', () => {
      const result = delegatedSign(ed25519Private, { data: '' })
      expect(result.signature).toBeTruthy()

      const valid = crypto.verify(
        null,
        Buffer.from(''),
        crypto.createPublicKey(ed25519Public),
        Buffer.from(result.signature, 'base64'),
      )
      expect(valid).toBe(true)
    })

    it('signs empty Buffer data', () => {
      const data = Buffer.alloc(0)
      const result = delegatedSign(ed25519Private, { data })
      expect(result.signature).toBeTruthy()

      const valid = crypto.verify(
        null,
        data,
        crypto.createPublicKey(ed25519Public),
        Buffer.from(result.signature, 'base64'),
      )
      expect(valid).toBe(true)
    })
  })
})
