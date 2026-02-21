/**
 * VaultClaims validation and in-memory token blocklist.
 *
 * @packageDocumentation
 */

import type { VaultClaims } from '../types.js'
import {
  TokenExpiredError,
  TokenRevokedError,
  UsageLimitExceededError,
  VaultError,
} from '../errors.js'

/**
 * Maximum number of JTIs the in-memory blocklist will retain.
 * When the cap is reached, the oldest inserted entry is evicted (FIFO/LRU).
 * This prevents unbounded growth for long-running processes.
 */
const BLOCKLIST_MAX_SIZE = 10_000

/**
 * In-memory blocklist for revoked token JTIs. This is process-local and non-persistent.
 * For production use, a distributed blocklist (e.g., Redis) should be layered on top.
 *
 * A Map is used instead of a Set because Map preserves insertion order, which
 * allows O(1) eviction of the oldest entry (first key in iteration order).
 * The map values are always `true` — only the keys matter for lookup.
 */
const blocklist = new Map<string, true>()

/**
 * Adds a JTI to the in-memory blocklist, preventing further use of that token.
 * If the blocklist has reached its maximum size, the oldest entry is evicted first.
 *
 * @param jti - The unique token ID to block
 */
export function blockToken(jti: string): void {
  if (blocklist.has(jti)) {
    // Already blocked — re-inserting would not change insertion order in Map,
    // so we delete and re-add to refresh the recency position.
    blocklist.delete(jti)
  } else if (blocklist.size >= BLOCKLIST_MAX_SIZE) {
    // Evict the oldest entry (first key in insertion-order iteration).
    const oldestKey = blocklist.keys().next().value
    if (oldestKey !== undefined) {
      blocklist.delete(oldestKey)
    }
  }
  blocklist.set(jti, true)
}

/**
 * Returns true if the given JTI has been blocked.
 *
 * @param jti - The unique token ID to check
 */
export function isBlocked(jti: string): boolean {
  return blocklist.has(jti)
}

/**
 * Clears all blocked JTIs from the in-memory blocklist.
 * Primarily intended for use in tests.
 */
export function clearBlocklist(): void {
  blocklist.clear()
}

/**
 * Validates all claims in a VaultClaims payload.
 *
 * Checks performed:
 * - Required fields present (jti, exp, iat, sub, exe, tid, bkd, val, ref)
 * - Token is not expired (exp vs. current time)
 * - Token is not on the blocklist
 * - Usage limit (use) is not exceeded if a positive limit is set
 * - Trust tier (tid) is valid (1, 2, or 3)
 *
 * @param claims - VaultClaims payload to validate
 * @param usedCount - How many times the token has been used already (for `use` limit checking)
 * @throws TokenExpiredError if the token is expired
 * @throws TokenRevokedError if the token has been blocked
 * @throws UsageLimitExceededError if the usage count has been exhausted
 * @throws VaultError for missing or malformed required fields
 */
export function validateClaims(claims: VaultClaims, usedCount = 0): void {
  // Validate required string fields are non-empty
  if (claims.jti.trim() === '') {
    throw new VaultError('Invalid token: jti must not be empty')
  }
  if (claims.sub.trim() === '') {
    throw new VaultError('Invalid token: sub must not be empty')
  }
  if (claims.exe.trim() === '') {
    throw new VaultError('Invalid token: exe must not be empty')
  }
  if (claims.bkd.trim() === '') {
    throw new VaultError('Invalid token: bkd must not be empty')
  }
  if (claims.val.trim() === '') {
    throw new VaultError('Invalid token: val must not be empty')
  }
  if (claims.ref.trim() === '') {
    throw new VaultError('Invalid token: ref must not be empty')
  }

  // Validate timestamp ordering
  if (claims.iat > claims.exp) {
    throw new VaultError('Invalid token: iat must not be after exp')
  }

  // Check expiration
  const nowSec = Math.floor(Date.now() / 1000)
  if (nowSec >= claims.exp) {
    throw new TokenExpiredError(
      `Token expired at ${String(claims.exp)} (now: ${String(nowSec)})`,
      false,
    )
  }

  // Check blocklist
  if (isBlocked(claims.jti)) {
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
