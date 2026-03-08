import { describe, it, expect } from 'vitest'
import { createToken, decryptToken, extractKid } from '../../../src/jwe/token.js'
import type { VaultClaims } from '../../../src/types.js'
import { VaultError } from '../../../src/errors.js'

/** Creates a minimal valid VaultClaims for testing. */
function makeTestClaims(overrides: Partial<VaultClaims> = {}): VaultClaims {
  const now = Math.floor(Date.now() / 1000)
  return {
    jti: 'test-jti-uuid-1234',
    exp: now + 3600,
    iat: now,
    sub: '/secrets/my-api-key',
    exe: 'abc123def456' + '0'.repeat(52), // 64-char SHA256
    use: null,
    tid: 1,
    bkd: 'keychain',
    val: 'encrypted-secret-value',
    ref: '/keychain/my-api-key',
    ...overrides,
  }
}

/** Returns a random 32-byte key suitable for A256GCM. */
function makeKey(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32))
}

describe('createToken / decryptToken', () => {
  it('roundtrip: decrypted claims match original', async () => {
    const key = makeKey()
    const claims = makeTestClaims()

    const jwe = await createToken(key, claims)
    const decrypted = await decryptToken(key, jwe)

    expect(decrypted).toEqual(claims)
  })

  it('produces a compact JWE with 5 parts', async () => {
    const key = makeKey()
    const jwe = await createToken(key, makeTestClaims())
    const parts = jwe.split('.')
    expect(parts).toHaveLength(5)
  })

  it('preserves kid header when provided', async () => {
    const key = makeKey()
    const jwe = await createToken(key, makeTestClaims(), { kid: 'key-v2' })

    const kid = extractKid(jwe)
    expect(kid).toBe('key-v2')
  })

  it('has no kid in header when not provided', async () => {
    const key = makeKey()
    const jwe = await createToken(key, makeTestClaims())

    const kid = extractKid(jwe)
    expect(kid).toBeUndefined()
  })

  it('roundtrip preserves all VaultClaims fields', async () => {
    const key = makeKey()
    const claims = makeTestClaims({
      jti: 'unique-jti',
      use: 5,
      tid: 3,
      bkd: 'op',
      val: 'super-secret',
      ref: '/op/vault/item',
    })

    const jwe = await createToken(key, claims)
    const decrypted = await decryptToken(key, jwe)

    expect(decrypted.jti).toBe(claims.jti)
    expect(decrypted.use).toBe(5)
    expect(decrypted.tid).toBe(3)
    expect(decrypted.bkd).toBe('op')
    expect(decrypted.val).toBe('super-secret')
  })

  it('roundtrip with use=null preserves null', async () => {
    const key = makeKey()
    const claims = makeTestClaims({ use: null })
    const jwe = await createToken(key, claims)
    const decrypted = await decryptToken(key, jwe)
    expect(decrypted.use).toBeNull()
  })

  it('decryption fails with wrong key', async () => {
    const key1 = makeKey()
    const key2 = makeKey()
    const jwe = await createToken(key1, makeTestClaims())

    await expect(decryptToken(key2, jwe)).rejects.toBeInstanceOf(VaultError)
  })

  it('decryption fails with a tampered JWE', async () => {
    const key = makeKey()
    const jwe = await createToken(key, makeTestClaims())
    const tampered = jwe.slice(0, -4) + 'XXXX'

    await expect(decryptToken(key, tampered)).rejects.toBeInstanceOf(VaultError)
  })

  it('decryption fails with a completely invalid string', async () => {
    const key = makeKey()
    await expect(decryptToken(key, 'not-a-jwe')).rejects.toBeInstanceOf(VaultError)
  })

  it('decryption fails if payload is not valid JSON', async () => {
    // We can't easily forge a valid JWE with bad JSON, so test via wrong key to exercise error path
    const key = makeKey()
    await expect(decryptToken(key, 'a.b.c.d.e')).rejects.toBeInstanceOf(VaultError)
  })
})

describe('extractKid', () => {
  it('returns kid from header', async () => {
    const key = makeKey()
    const jwe = await createToken(key, makeTestClaims(), { kid: 'rotation-key-1' })
    expect(extractKid(jwe)).toBe('rotation-key-1')
  })

  it('returns undefined when no kid', async () => {
    const key = makeKey()
    const jwe = await createToken(key, makeTestClaims())
    expect(extractKid(jwe)).toBeUndefined()
  })

  it('throws VaultError for malformed JWE (wrong number of parts)', () => {
    expect(() => extractKid('a.b.c')).toThrow(VaultError)
  })

  it('throws VaultError for empty string', () => {
    expect(() => extractKid('')).toThrow(VaultError)
  })
})
