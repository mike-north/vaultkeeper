import { describe, it, expect } from 'vitest'
import {
  CapabilityToken,
  createCapabilityToken,
  validateCapabilityToken,
} from '../../../src/identity/session.js'
import { AuthorizationDeniedError } from '../../../src/errors.js'
import type { VaultClaims } from '../../../src/identity/types.js'

function makeClaims(overrides: Partial<VaultClaims> = {}): VaultClaims {
  return {
    jti: 'test-jti-001',
    exp: Math.floor(Date.now() / 1000) + 3600,
    iat: Math.floor(Date.now() / 1000),
    sub: 'test/secret',
    exe: 'dev',
    use: null,
    tid: 3,
    bkd: 'file',
    val: 'encrypted-value',
    ref: '/path/to/secret',
    ...overrides,
  }
}

describe('CapabilityToken', () => {
  it('is an instance of CapabilityToken', () => {
    const token = createCapabilityToken(makeClaims())
    expect(token).toBeInstanceOf(CapabilityToken)
  })

  it('has no enumerable properties exposing claims', () => {
    const token = createCapabilityToken(makeClaims())
    const keys = Object.keys(token)
    expect(keys).toHaveLength(0)
  })

  it('toString does not contain claim data', () => {
    const claims = makeClaims({ sub: 'super-secret-path' })
    const token = createCapabilityToken(claims)
    const str = token.toString()
    expect(str).not.toContain('super-secret-path')
    expect(str).not.toContain('encrypted-value')
  })

  it('cannot be JSON-serialized to reveal claims', () => {
    const token = createCapabilityToken(makeClaims({ val: 'secret-value' }))
    const serialized = JSON.stringify(token)
    expect(serialized).not.toContain('secret-value')
  })
})

describe('createCapabilityToken', () => {
  it('creates a distinct token for each call', () => {
    const claims = makeClaims()
    const t1 = createCapabilityToken(claims)
    const t2 = createCapabilityToken(claims)
    expect(t1).not.toBe(t2)
  })

  it('stores the claims retrievable by validateCapabilityToken', () => {
    const claims = makeClaims({ sub: 'path/to/secret', jti: 'unique-id' })
    const token = createCapabilityToken(claims)
    const retrieved = validateCapabilityToken(token)
    expect(retrieved).toEqual(claims)
  })
})

describe('validateCapabilityToken', () => {
  it('returns the exact claims object used to create the token', () => {
    const claims = makeClaims()
    const token = createCapabilityToken(claims)
    const result = validateCapabilityToken(token)
    expect(result).toEqual(claims)
    expect(result.jti).toBe(claims.jti)
    expect(result.sub).toBe(claims.sub)
  })

  it('throws AuthorizationDeniedError for a token not created by createCapabilityToken', () => {
    const forgery = new CapabilityToken()
    expect(() => validateCapabilityToken(forgery)).toThrow(AuthorizationDeniedError)
    expect(() => validateCapabilityToken(forgery)).toThrow('Invalid or unrecognized capability token')
  })

  it('throws AuthorizationDeniedError for a plain object cast-free forgery attempt', () => {
    // Simulate an attacker constructing their own CapabilityToken subclass
    class FakeToken extends CapabilityToken {}
    const fake = new FakeToken()
    expect(() => validateCapabilityToken(fake)).toThrow(AuthorizationDeniedError)
    expect(() => validateCapabilityToken(fake)).toThrow('Invalid or unrecognized capability token')
  })

  it('each token returns its own distinct claims', () => {
    const claimsA = makeClaims({ jti: 'token-a', sub: 'path/a' })
    const claimsB = makeClaims({ jti: 'token-b', sub: 'path/b' })
    const tokenA = createCapabilityToken(claimsA)
    const tokenB = createCapabilityToken(claimsB)

    expect(validateCapabilityToken(tokenA).jti).toBe('token-a')
    expect(validateCapabilityToken(tokenB).jti).toBe('token-b')
  })
})
