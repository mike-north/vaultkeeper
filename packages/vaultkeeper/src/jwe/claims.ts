/**
 * VaultClaims validation and in-memory token blocklist.
 */

import type { VaultClaims } from '../types.js'
import {
  TokenExpiredError,
  TokenRevokedError,
  UnreachableError,
  UsageLimitExceededError,
  VaultError,
} from '../errors.js'
import { tokenExpiryTime } from './expiry-clock.js'

/** Size at which the blocklist attempts to reclaim expired entries. */
const BLOCKLIST_SWEEP_THRESHOLD = 10_000

/** Process-local denial records, keyed by JTI and retained through expiry. */
const blocklist = new Map<string, number>()

/** Whole second of the last pressure sweep, limiting full scans under load. */
let lastBlocklistSweep: number | undefined

/**
 * Blocks a JTI without evicting other live denials.
 *
 * @param jti - The unique token ID to block
 * @param expiresAt - Epoch second when the denial can be discarded. Defaults
 *   to an indefinite denial. Repeated blocks can only extend the denial.
 * @internal
 */
export function blockToken(jti: string, expiresAt = Number.POSITIVE_INFINITY): void {
  const now = tokenExpiryTime()
  const sweepSecond = Math.floor(now)
  if (blocklist.size >= BLOCKLIST_SWEEP_THRESHOLD && lastBlocklistSweep !== sweepSecond) {
    for (const [blockedJti, expiry] of blocklist) {
      if (expiry <= now) {
        blocklist.delete(blockedJti)
      }
    }
    lastBlocklistSweep = sweepSecond
  }
  if (expiresAt > now) {
    blocklist.set(jti, Math.max(blocklist.get(jti) ?? expiresAt, expiresAt))
  }
}

/**
 * Returns true if the given JTI has a live denial.
 *
 * @param jti - The unique token ID to check
 * @param now - Authorization time snapshot, shared with the claim expiry check
 * @internal
 */
export function isBlocked(jti: string, now = tokenExpiryTime()): boolean {
  const expiry = blocklist.get(jti)
  if (expiry === undefined) return false
  if (expiry <= now) {
    blocklist.delete(jti)
    return false
  }
  return true
}

/**
 * Clears all blocked JTIs from the in-memory blocklist.
 * Primarily intended for use in tests.
 * @internal
 */
export function clearBlocklist(): void {
  blocklist.clear()
  lastBlocklistSweep = undefined
}

/**
 * Check the inclusive JWE cutoff against the caller's clock snapshot, including
 * fractional NumericDates. Keep whole-second diagnostics for whole-second deadlines.
 * @internal
 */
export function getTokenExpiryError(exp: number, nowSec: number): TokenExpiredError | undefined {
  if (nowSec >= exp) {
    const reportedNow = Number.isInteger(exp) ? Math.floor(nowSec) : nowSec
    return new TokenExpiredError(
      `Token expired at ${String(exp)} (now: ${String(reportedNow)})`,
      false,
    )
  }
  return undefined
}

/**
 * Validates all claims in a VaultClaims payload.
 * @internal
 *
 * Dispatches on {@link VaultClaims.kty} (`kty` omitted is treated as `'secret'`
 * for backward compatibility with tokens minted before this discriminator
 * existed — see the in-memory `isSigningClaims` split in `identity/session.ts`
 * for the analogous pattern):
 *
 * - A **secret** claim (`kty` omitted or `'secret'`) requires a non-empty
 *   `bkd` and `val`.
 * - A **signing-key lease** (`kty: 'signing-key'`) MUST NOT carry a `val`,
 *   requires a non-empty `kid`, and requires `kgen` to be present — a lease
 *   missing `kgen` is rejected outright, never defaulted to generation 0
 *   (fail-closed; the revocation design depends on this being explicit).
 *
 * Checks performed for every claim, regardless of kind:
 * - Required fields present (jti, sub, exe, ref)
 * - Token is not expired (exp vs. current time)
 * - Token is not on the blocklist
 * - Usage limit (use) is not exceeded if a positive limit is set
 *
 * @param claims - VaultClaims payload to validate
 * @param usedCount - How many times the token has been used already (for `use` limit checking)
 * @param now - Authorization time snapshot, shared with usage reclamation
 * @throws TokenExpiredError if the token is expired
 * @throws TokenRevokedError if the token has been blocked
 * @throws UsageLimitExceededError if the usage count has been exhausted
 * @throws VaultError for missing or malformed required fields
 * @throws UnreachableError if `kty` is present but not a recognized
 * {@link ClaimsKind}
 */
export function validateClaims(claims: VaultClaims, usedCount = 0, now = tokenExpiryTime()): void {
  // Validate required string fields shared by every claims kind.
  if (claims.jti.trim() === '') {
    throw new VaultError('Invalid token: jti must not be empty')
  }
  if (claims.sub.trim() === '') {
    throw new VaultError('Invalid token: sub must not be empty')
  }
  if (claims.exe.trim() === '') {
    throw new VaultError('Invalid token: exe must not be empty')
  }
  if (claims.ref.trim() === '') {
    throw new VaultError('Invalid token: ref must not be empty')
  }

  // A `switch` (rather than `if`/`else if`) keeps the `default` branch below
  // reachable to the type checker's `no-unnecessary-condition` lint even
  // though `ClaimsKind` only has two known values — it exists as a runtime
  // defense against a `claims` value that did not actually go through
  // `parseVaultClaims`'s narrowing (this function is also exercised directly
  // in tests, and could in principle be called by some other caller with an
  // unvalidated payload).
  switch (claims.kty) {
    case 'signing-key': {
      // Signing-key lease: no secret value ever travels on this claims
      // shape — a `val` key present at all (even empty/whitespace) is
      // rejected, not just a non-empty one.
      if (claims.val !== undefined) {
        throw new VaultError('Invalid token: signing lease must not carry a val')
      }
      if (claims.kid === undefined || claims.kid.trim() === '') {
        throw new VaultError('Invalid token: kid must not be empty')
      }
      if (claims.kgen === undefined) {
        throw new VaultError('Invalid token: kgen is required for a signing lease')
      }
      // Cross-language invariant: the Rust core deserializes kgen as a u64,
      // so a fractional, negative, NaN, or unsafely-large value would mint a
      // token Rust can never accept. Enforce the same domain here.
      if (!Number.isSafeInteger(claims.kgen) || claims.kgen < 0) {
        throw new VaultError('Invalid token: kgen must be a non-negative integer')
      }
      break
    }
    case 'secret':
    case undefined: {
      // Ordinary secret claim (kty omitted or 'secret').
      if (claims.bkd === undefined || claims.bkd.trim() === '') {
        throw new VaultError('Invalid token: bkd must not be empty')
      }
      if (claims.val === undefined || claims.val.trim() === '') {
        throw new VaultError('Invalid token: val must not be empty')
      }
      // Cross-shape field leakage: a secret claim must never carry
      // signing-lease-only fields, even if some future caller mistakenly
      // sets them alongside a secret payload.
      if (claims.kid !== undefined || claims.kgen !== undefined || claims.pres !== undefined) {
        throw new VaultError(
          'Invalid token: secret claim must not carry signing-lease fields (kid/kgen/pres)',
        )
      }
      break
    }
    default: {
      // `kty` present but neither 'secret' nor 'signing-key' — the Rust core
      // rejects this at deserialization (ClaimsKind has no catch-all
      // variant); mirror that fail-closed behavior here rather than
      // silently treating an unrecognized kind as a secret claim. Routed
      // through UnreachableError (rather than a bare VaultError) so that
      // adding a new ClaimsKind member without a matching case here becomes
      // a compile error at this switch, not just a runtime throw.
      throw new UnreachableError(claims.kty, 'Invalid token: unrecognized claim kind')
    }
  }

  // Validate timestamp ordering
  if (claims.iat > claims.exp) {
    throw new VaultError('Invalid token: iat must not be after exp')
  }

  const expiryError = getTokenExpiryError(claims.exp, now)
  if (expiryError !== undefined) {
    throw expiryError
  }

  // Check blocklist
  if (isBlocked(claims.jti, now)) {
    throw new TokenRevokedError(`Token ${claims.jti} has been revoked`)
  }

  // Check usage limit
  if (claims.use !== null) {
    if (claims.use <= 0) {
      throw new UsageLimitExceededError(
        `Token ${claims.jti} has a non-positive usage limit: ${String(claims.use)}`,
      )
    }
    if (usedCount >= claims.use) {
      throw new UsageLimitExceededError(
        `Token ${claims.jti} usage limit of ${String(claims.use)} exceeded (used: ${String(usedCount)})`,
      )
    }
  }
}
