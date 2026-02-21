import { describe, it, expect, beforeEach } from 'vitest'
import { validateClaims, blockToken, isBlocked, clearBlocklist } from '../../../src/jwe/claims.js'
import type { VaultClaims } from '../../../src/types.js'
import {
  TokenExpiredError,
  TokenRevokedError,
  UsageLimitExceededError,
  VaultError,
} from '../../../src/errors.js'

/** Builds a valid VaultClaims that passes all validation checks. */
function makeValidClaims(overrides: Partial<VaultClaims> = {}): VaultClaims {
  const now = Math.floor(Date.now() / 1000)
  return {
    jti: 'valid-jti-uuid-1234',
    exp: now + 3600,
    iat: now,
    sub: '/secrets/db-password',
    exe: 'a'.repeat(64),
    use: null,
    tid: 1,
    bkd: 'keychain',
    val: 'encrypted-value',
    ref: '/keychain/db-password',
    ...overrides,
  }
}

describe('blockToken / isBlocked', () => {
  beforeEach(() => {
    clearBlocklist()
  })

  it('newly created JTI is not blocked', () => {
    expect(isBlocked('some-jti')).toBe(false)
  })

  it('blocked JTI returns true for isBlocked', () => {
    blockToken('blocked-jti')
    expect(isBlocked('blocked-jti')).toBe(true)
  })

  it('blocking one JTI does not affect others', () => {
    blockToken('blocked-jti')
    expect(isBlocked('other-jti')).toBe(false)
  })

  it('blocking same JTI multiple times is idempotent', () => {
    blockToken('jti-a')
    blockToken('jti-a')
    expect(isBlocked('jti-a')).toBe(true)
  })

  it('clearBlocklist removes all blocked JTIs', () => {
    blockToken('jti-a')
    blockToken('jti-b')
    clearBlocklist()
    expect(isBlocked('jti-a')).toBe(false)
    expect(isBlocked('jti-b')).toBe(false)
  })
})

describe('validateClaims', () => {
  beforeEach(() => {
    clearBlocklist()
  })

  describe('positive cases', () => {
    it('accepts a fully valid claims object', () => {
      expect(() => {
        validateClaims(makeValidClaims())
      }).not.toThrow()
    })

    it('accepts use=null (unlimited)', () => {
      expect(() => {
        validateClaims(makeValidClaims({ use: null }))
      }).not.toThrow()
    })

    it('accepts use=1 when usedCount=0', () => {
      expect(() => {
        validateClaims(makeValidClaims({ use: 1 }), 0)
      }).not.toThrow()
    })

    it('accepts use=5 when usedCount=4', () => {
      expect(() => {
        validateClaims(makeValidClaims({ use: 5 }), 4)
      }).not.toThrow()
    })

    it('accepts tid=2', () => {
      expect(() => {
        validateClaims(makeValidClaims({ tid: 2 }))
      }).not.toThrow()
    })

    it('accepts tid=3', () => {
      expect(() => {
        validateClaims(makeValidClaims({ tid: 3 }))
      }).not.toThrow()
    })

    it('accepts future expiry one second from now', () => {
      const now = Math.floor(Date.now() / 1000)
      expect(() => {
        validateClaims(makeValidClaims({ exp: now + 1 }))
      }).not.toThrow()
    })
  })

  describe('expiration checks', () => {
    it('throws TokenExpiredError when exp is in the past', () => {
      const past = Math.floor(Date.now() / 1000) - 3600
      const claims = makeValidClaims({ iat: past - 60, exp: past })
      expect(() => {
        validateClaims(claims)
      }).toThrow(TokenExpiredError)
    })

    it('throws TokenExpiredError when exp equals now', () => {
      const now = Math.floor(Date.now() / 1000)
      const claims = makeValidClaims({ iat: now - 3600, exp: now })
      expect(() => {
        validateClaims(claims)
      }).toThrow(TokenExpiredError)
    })

    it('TokenExpiredError has canRefresh=false', () => {
      const past = Math.floor(Date.now() / 1000) - 3600
      const claims = makeValidClaims({ iat: past - 60, exp: past })
      try {
        validateClaims(claims)
        expect.fail('should have thrown')
      } catch (err) {
        expect(err).toBeInstanceOf(TokenExpiredError)
        if (err instanceof TokenExpiredError) {
          expect(err.canRefresh).toBe(false)
        }
      }
    })
  })

  describe('blocklist checks', () => {
    it('throws TokenRevokedError for blocked JTI', () => {
      const claims = makeValidClaims({ jti: 'revoked-jti' })
      blockToken('revoked-jti')
      expect(() => {
        validateClaims(claims)
      }).toThrow(TokenRevokedError)
    })

    it('does not throw for unblocked JTI after clearing blocklist', () => {
      const claims = makeValidClaims({ jti: 'was-blocked' })
      blockToken('was-blocked')
      clearBlocklist()
      expect(() => {
        validateClaims(claims)
      }).not.toThrow()
    })
  })

  describe('usage limit checks', () => {
    it('throws UsageLimitExceededError when usedCount equals use', () => {
      const claims = makeValidClaims({ use: 3 })
      expect(() => {
        validateClaims(claims, 3)
      }).toThrow(UsageLimitExceededError)
    })

    it('throws UsageLimitExceededError when usedCount exceeds use', () => {
      const claims = makeValidClaims({ use: 3 })
      expect(() => {
        validateClaims(claims, 10)
      }).toThrow(UsageLimitExceededError)
    })

    it('throws UsageLimitExceededError for use=0 even with usedCount=0', () => {
      const claims = makeValidClaims({ use: 0 })
      expect(() => {
        validateClaims(claims, 0)
      }).toThrow(UsageLimitExceededError)
    })

    it('does not throw for use=1 usedCount=0', () => {
      expect(() => {
        validateClaims(makeValidClaims({ use: 1 }), 0)
      }).not.toThrow()
    })

    it('does not throw for use=null regardless of usedCount', () => {
      expect(() => {
        validateClaims(makeValidClaims({ use: null }), 9999)
      }).not.toThrow()
    })
  })

  describe('required field validation', () => {
    it('throws VaultError for empty jti', () => {
      expect(() => {
        validateClaims(makeValidClaims({ jti: '' }))
      }).toThrow(VaultError)
    })

    it('throws VaultError for whitespace-only jti', () => {
      expect(() => {
        validateClaims(makeValidClaims({ jti: '   ' }))
      }).toThrow(VaultError)
    })

    it('throws VaultError for empty sub', () => {
      expect(() => {
        validateClaims(makeValidClaims({ sub: '' }))
      }).toThrow(VaultError)
    })

    it('throws VaultError for empty exe', () => {
      expect(() => {
        validateClaims(makeValidClaims({ exe: '' }))
      }).toThrow(VaultError)
    })

    it('throws VaultError for empty bkd', () => {
      expect(() => {
        validateClaims(makeValidClaims({ bkd: '' }))
      }).toThrow(VaultError)
    })

    it('throws VaultError for empty val', () => {
      expect(() => {
        validateClaims(makeValidClaims({ val: '' }))
      }).toThrow(VaultError)
    })

    it('throws VaultError for empty ref', () => {
      expect(() => {
        validateClaims(makeValidClaims({ ref: '' }))
      }).toThrow(VaultError)
    })

    it('throws VaultError when iat is after exp', () => {
      const now = Math.floor(Date.now() / 1000)
      const claims = makeValidClaims({ iat: now + 7200, exp: now + 3600 })
      expect(() => {
        validateClaims(claims)
      }).toThrow(VaultError)
    })
  })
})
