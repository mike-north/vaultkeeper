import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
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

    describe('future expiry (fixed clock)', () => {
      // Regression test for #208: this test previously read Date.now() once to
      // build a claim expiring 1 second in the future, then let validateClaims()
      // read Date.now() again independently. If the real clock crossed a second
      // boundary between those two reads, the claim would appear expired,
      // flaking CI. Fake timers pin the clock so both reads see the same instant.
      beforeEach(() => {
        vi.useFakeTimers()
        vi.setSystemTime(new Date('2024-01-15T10:00:00.000Z'))
      })
      afterEach(() => {
        vi.useRealTimers()
      })

      it('accepts future expiry one second from now', () => {
        const now = Math.floor(Date.now() / 1000)
        expect(() => {
          validateClaims(makeValidClaims({ exp: now + 1 }))
        }).not.toThrow()
      })
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

  // ─── kty discrimination (issue #280/#287) ──────────────────────────────

  /** Builds a well-formed signing-key lease claims payload. */
  function makeLeaseClaims(overrides: Partial<VaultClaims> = {}): VaultClaims {
    const now = Math.floor(Date.now() / 1000)
    return {
      jti: 'lease-jti-1',
      exp: now + 3600,
      iat: now,
      sub: 'release-key',
      exe: 'a'.repeat(64),
      use: null,
      tid: 1,
      ref: 'release-key',
      kty: 'signing-key',
      kid: 'kid-abc123',
      kgen: 1,
      ...overrides,
    }
  }

  describe('kty discrimination', () => {
    it('accepts a well-formed signing-key lease', () => {
      expect(() => {
        validateClaims(makeLeaseClaims())
      }).not.toThrow()
    })

    it('rejects a fractional kgen — Rust deserializes kgen as u64, so a non-integer would mint a token Rust can never accept', () => {
      expect(() => {
        validateClaims(makeLeaseClaims({ kgen: 1.5 }))
      }).toThrow('Invalid token: kgen must be a non-negative integer')
    })

    it('rejects a negative kgen', () => {
      expect(() => {
        validateClaims(makeLeaseClaims({ kgen: -1 }))
      }).toThrow('Invalid token: kgen must be a non-negative integer')
    })

    it('rejects a NaN kgen', () => {
      expect(() => {
        validateClaims(makeLeaseClaims({ kgen: Number.NaN }))
      }).toThrow('Invalid token: kgen must be a non-negative integer')
    })

    it('accepts kgen 0 — a valid first generation, distinct from a missing kgen', () => {
      expect(() => {
        validateClaims(makeLeaseClaims({ kgen: 0 }))
      }).not.toThrow()
    })

    it('rejects a signing lease carrying an empty val — no empty-string exemption', () => {
      expect(() => {
        validateClaims(makeLeaseClaims({ val: '' }))
      }).toThrow('Invalid token: signing lease must not carry a val')
    })

    it('rejects a signing lease carrying a whitespace-only val — no exemption', () => {
      expect(() => {
        validateClaims(makeLeaseClaims({ val: '   ' }))
      }).toThrow('Invalid token: signing lease must not carry a val')
    })

    it('rejects a signing lease with a whitespace-only kid', () => {
      expect(() => {
        validateClaims(makeLeaseClaims({ kid: '   ' }))
      }).toThrow('Invalid token: kid must not be empty')
    })

    it('rejects a secret claim carrying a signing-lease kid', () => {
      expect(() => {
        validateClaims(makeValidClaims({ kid: 'kid-should-not-be-here' }))
      }).toThrow('Invalid token: secret claim must not carry signing-lease fields (kid/kgen/pres)')
    })

    it('rejects a secret claim carrying a signing-lease kgen', () => {
      expect(() => {
        validateClaims(makeValidClaims({ kgen: 1 }))
      }).toThrow('Invalid token: secret claim must not carry signing-lease fields (kid/kgen/pres)')
    })

    it('rejects a secret claim carrying a signing-lease pres', () => {
      expect(() => {
        validateClaims(
          makeValidClaims({
            pres: { op: 'sign', at: Math.floor(Date.now() / 1000), method: 'touch', backend: 'yubikey' },
          }),
        )
      }).toThrow('Invalid token: secret claim must not carry signing-lease fields (kid/kgen/pres)')
    })

    it('rejects an unrecognized kty rather than silently treating it as a secret claim', () => {
      const claims = makeValidClaims()
      const record: Record<string, unknown> = { ...claims, kty: 'wat' }
      if (!isRecordVaultClaimsShapedIgnoringKty(record)) {
        throw new Error('unreachable: base claims always satisfy the minimal shape')
      }
      expect(() => {
        validateClaims(record)
      }).toThrow('Invalid token: unrecognized claim kind kty=wat')
    })
  })
})

/**
 * Type predicate used only to build a deliberately malformed claims payload
 * (an unrecognized `kty`) for testing `validateClaims`'s own defense-in-depth
 * rejection. `parseVaultClaims` (the JWE-decrypt-time parser,
 * `packages/vaultkeeper/src/jwe/token.ts`) already rejects this earlier in
 * the real pipeline and is not exercised by this path — this validates the
 * minimal shape `validateClaims` itself relies on, treating `kty` as an
 * arbitrary string rather than requiring it to be a known `ClaimsKind`.
 */
function isRecordVaultClaimsShapedIgnoringKty(value: unknown): value is VaultClaims {
  if (typeof value !== 'object' || value === null) return false
  const record: Record<string, unknown> = { ...value }
  return (
    typeof record.jti === 'string' &&
    typeof record.exp === 'number' &&
    typeof record.iat === 'number' &&
    typeof record.sub === 'string' &&
    typeof record.exe === 'string' &&
    typeof record.ref === 'string'
  )
}
