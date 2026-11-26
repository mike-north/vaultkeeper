import { describe, it, expect } from 'vitest'
import { createToken, decryptToken, extractKid } from '../../../src/jwe/token.js'
import type { VaultClaims } from '../../../src/types.js'
import { VaultError, InvalidTokenError } from '../../../src/errors.js'
import { validateClaims } from '../../../src/jwe/claims.js'

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

/** Creates a well-formed signing-key lease VaultClaims for testing. */
function makeTestLeaseClaims(overrides: Partial<VaultClaims> = {}): VaultClaims {
  const now = Math.floor(Date.now() / 1000)
  return {
    jti: 'test-jti-lease-uuid-1234',
    exp: now + 3600,
    iat: now,
    sub: 'release-key',
    exe: 'abc123def456' + '0'.repeat(52),
    use: null,
    tid: 1,
    ref: 'release-key',
    kty: 'signing-key',
    kid: 'kid-abc123',
    kgen: 1,
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
    await expect(decryptToken(key, 'not-a-jwe')).rejects.toBeInstanceOf(InvalidTokenError)
  })

  it('decryption fails if payload is not valid JSON', async () => {
    // We can't easily forge a valid JWE with bad JSON, so test via wrong key to exercise error path
    const key = makeKey()
    await expect(decryptToken(key, 'a.b.c.d.e')).rejects.toBeInstanceOf(VaultError)
  })

  // Regression test for issue #287: `parseVaultClaims` used to hard-require
  // `bkd`/`val` as non-optional strings and silently drop `kty`/`kid`/`kgen`/
  // `pres`, so a real signing-key lease JWE failed inside `decryptToken`
  // before `validateClaims` (the actual secret-vs-lease business-rule
  // chokepoint) ever ran. This exercises the full real pipeline —
  // `createToken` → `decryptToken` → `validateClaims` — for both claim
  // shapes, end to end.
  describe('createToken -> decryptToken -> validateClaims round trip (issue #287)', () => {
    it('accepts a well-formed signing-key lease', async () => {
      const key = makeKey()
      const claims = makeTestLeaseClaims()

      const jwe = await createToken(key, claims)
      const decrypted = await decryptToken(key, jwe)

      expect(decrypted.kty).toBe('signing-key')
      expect(decrypted.kid).toBe('kid-abc123')
      expect(decrypted.kgen).toBe(1)
      expect(decrypted.val).toBeUndefined()
      expect(() => {
        validateClaims(decrypted)
      }).not.toThrow()
    })

    it('still accepts an unchanged (non-lease) secret token', async () => {
      const key = makeKey()
      const claims = makeTestClaims()

      const jwe = await createToken(key, claims)
      const decrypted = await decryptToken(key, jwe)

      expect(decrypted.kty).toBeUndefined()
      expect(decrypted.bkd).toBe('keychain')
      expect(decrypted.val).toBe('encrypted-secret-value')
      expect(() => {
        validateClaims(decrypted)
      }).not.toThrow()
    })
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

  it('throws InvalidTokenError for malformed JWE (wrong number of parts)', () => {
    expect(() => extractKid('a.b.c')).toThrow(InvalidTokenError)
  })

  it('throws InvalidTokenError for empty string', () => {
    expect(() => extractKid('')).toThrow(InvalidTokenError)
  })
})
