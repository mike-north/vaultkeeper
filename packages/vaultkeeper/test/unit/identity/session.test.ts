import { describe, it, expect } from 'vitest'
import * as publicApi from '../../../src/index.js'
import {
  CapabilityToken,
  createCapabilityToken,
  createSigningCapabilityToken,
  validateCapabilityToken,
  isSigningClaims,
} from '../../../src/identity/session.js'
import { AuthorizationDeniedError } from '../../../src/errors.js'
import type { VaultClaims, SigningClaims } from '../../../src/identity/types.js'

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

// Regression guard for issue #74: the CapabilityToken doc promises there is no
// public API for reading claims, so both token helpers must stay internal — for
// different reasons. Exporting validateCapabilityToken would directly leak the
// secret, since it reads the claims (including the secret value) back out.
// Exporting createCapabilityToken would not read claims, but it mints a token
// around caller-supplied claims, letting callers forge tokens outside the
// authorize() flow and bypass its validation and usage tracking. Neither is
// exported.
describe('CapabilityToken public surface (issue #74)', () => {
  it('exports the CapabilityToken class', () => {
    expect('CapabilityToken' in publicApi).toBe(true)
  })

  it('does not export the internal token helpers', () => {
    // Asserts the source entrypoint's (src/index.ts) export surface. The issue
    // repro checks the built package at runtime
    // (`'validateCapabilityToken' in await import('vaultkeeper')`); both resolve
    // to the same export set, so this is the fast unit-level equivalent.
    expect('validateCapabilityToken' in publicApi).toBe(false)
    expect('createCapabilityToken' in publicApi).toBe(false)
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
    expect(() => validateCapabilityToken(forgery)).toThrow(
      'Invalid or unrecognized capability token',
    )
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

function makeSigningClaims(overrides: Partial<SigningClaims> = {}): SigningClaims {
  return { keyType: 'signing-key', kid: 'test-kid', backendRef: 'signing-key:test', ...overrides }
}

describe('isSigningClaims', () => {
  it('accepts well-formed signing claims', () => {
    expect(isSigningClaims(makeSigningClaims())).toBe(true)
  })

  it('accepts real claims from createSigningCapabilityToken', () => {
    const token = createSigningCapabilityToken(makeSigningClaims())
    expect(isSigningClaims(validateCapabilityToken(token))).toBe(true)
  })

  it('rejects ordinary secret claims (no keyType marker)', () => {
    expect(isSigningClaims(makeClaims())).toBe(false)
  })

  it('rejects signing claims with an empty kid', () => {
    expect(isSigningClaims(makeSigningClaims({ kid: '' }))).toBe(false)
  })

  it('rejects signing claims with an empty backendRef', () => {
    expect(isSigningClaims(makeSigningClaims({ backendRef: '' }))).toBe(false)
  })

  it('rejects a claims object carrying BOTH signing markers and secret material', () => {
    // Defense in depth: a hostile/malformed object that presents the signing
    // markers but also carries a `val` secret must never be treated as a
    // signing key. Object.assign attaches `val` at runtime while keeping a
    // SigningClaims-assignable static type (no cast needed).
    const both: SigningClaims = Object.assign(makeSigningClaims(), { val: 'super-secret' })
    expect(isSigningClaims(both)).toBe(false)
  })
})
