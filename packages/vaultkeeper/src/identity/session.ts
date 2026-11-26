/**
 * Capability token management.
 *
 * The module-private `WeakMap` binds each token to its issuer for its lifetime.
 * Claim lookup requires the issuing vault's private identity. A JWE capability
 * drops its claims once expiry is observed, retaining the issuer and deadline.
 */

import type { VaultClaims, SigningClaims } from './types.js'
import { AuthorizationDeniedError, TokenExpiredError } from '../errors.js'
import { getTokenExpiryError } from '../jwe/claims.js'

/**
 * The claims a capability token can wrap: either an ordinary secret's
 * {@link VaultClaims} or a signing key's {@link SigningClaims}. The two are
 * discriminated by the presence of a `keyType` field so secret-access and
 * signing paths can each reject the wrong kind of token.
 *
 * @internal
 */
export type StoredClaims = VaultClaims | SigningClaims

/**
 * An opaque handle to authorized secret or signing-key claims.
 *
 * {@link VaultKeeper.authorize} and {@link VaultKeeper.authorizeSigningKey}
 * return tokens bound to the issuing `VaultKeeper` instance. Claims and issuer
 * identity are held outside the token object. `toString()` returns only a debug
 * identifier.
 *
 * Pass a secret token to the issuer's {@link VaultKeeper.getSecret},
 * {@link VaultKeeper.fetch}, or {@link VaultKeeper.exec} method. Pass a signing
 * token to the issuer's {@link VaultKeeper.sign} method.
 *
 * @public
 */
export class CapabilityToken {
  // Private field ensures no public surface leaks claims.
  readonly #brand: symbol

  constructor() {
    this.#brand = Symbol('CapabilityToken')
  }

  /**
   * Return a non-enumerable identifier for debugging purposes only.
   * Does NOT expose claims.
   */
  toString(): string {
    return `[CapabilityToken ${this.#brand.toString()}]`
  }
}

/** Issuer-bound authority and the data retained at each stage of its lifetime. */
type CapabilityEntry = { readonly owner: symbol } & (
  | { readonly kind: 'jwe'; readonly claims: VaultClaims; readonly deadline: number }
  | { readonly kind: 'signing'; readonly claims: SigningClaims }
  | { readonly kind: 'expired'; readonly deadline: number }
)

/** Token identity controls the lifetime of the private authorization record. */
const claimsStore = new WeakMap<CapabilityToken, CapabilityEntry>()

/** Require the issuer before inspecting the token's kind, deadline, or claims. */
function requireCapabilityEntry(token: CapabilityToken, owner: symbol): CapabilityEntry {
  const entry = claimsStore.get(token)
  if (entry === undefined) {
    throw new AuthorizationDeniedError('Invalid or unrecognized capability token')
  }
  if (entry.owner !== owner) {
    throw new AuthorizationDeniedError('Capability token was issued by another vault instance')
  }
  return entry
}

/**
 * Create a capability token that wraps secret `claims`.
 * The claims are stored in a module-private `WeakMap` and cannot be reached
 * without calling `validateCapabilityToken`.
 * @param claims - Authorized secret claims.
 * @param owner - The issuing vault's private identity.
 * @internal
 */
export function createCapabilityToken(claims: VaultClaims, owner: symbol): CapabilityToken {
  const token = new CapabilityToken()
  claimsStore.set(token, { kind: 'jwe', owner, claims, deadline: claims.exp })
  return token
}

/**
 * Create a capability token that wraps signing-key `claims`.
 *
 * The claims carry only references (`kid`, `backendRef`, `keyType`) — never any
 * private key material — so a signing token can never leak a key even if the
 * WeakMap entry were somehow observed.
 * @param claims - Authorized signing-key claims.
 * @param owner - The issuing vault's private identity.
 * @internal
 */
export function createSigningCapabilityToken(
  claims: SigningClaims,
  owner: symbol,
): CapabilityToken {
  const token = new CapabilityToken()
  claimsStore.set(token, { kind: 'signing', owner, claims })
  return token
}

/**
 * Retrieve live claims for the vault that issued the token.
 *
 * @param token - The opaque capability presented for use.
 * @param owner - The consuming vault's private identity.
 * @param nowSec - The clock sample in epoch seconds for this expiry check.
 * @throws {AuthorizationDeniedError} If the token has no entry or its
 *   issuer differs from the consuming vault.
 * @throws {TokenExpiredError} If the JWE deadline has been reached.
 * @internal
 */
export function validateCapabilityToken(
  token: CapabilityToken,
  owner: symbol,
  nowSec = Date.now() / 1000,
): StoredClaims {
  const entry = requireCapabilityEntry(token, owner)
  if (entry.kind === 'signing') {
    return entry.claims
  }
  if (entry.kind === 'expired') {
    throw new TokenExpiredError(`Token expired at ${String(entry.deadline)}`, false)
  }
  const expiryError = getTokenExpiryError(entry.deadline, nowSec)
  if (expiryError !== undefined) {
    // Drop the claims and prevent a backwards clock correction from reviving them.
    claimsStore.set(token, { kind: 'expired', owner: entry.owner, deadline: entry.deadline })
    throw expiryError
  }
  return entry.claims
}

/**
 * Resolve the backend key reference carried by an in-memory signing capability.
 * Signing rejects JWE-backed capabilities by kind, even after their claims have
 * been cleared on expiry. Only secret access evaluates their JWE deadlines.
 * @param token - The opaque capability presented for signing.
 * @param owner - The consuming vault's private identity.
 * @throws {AuthorizationDeniedError} If the token is invalid, belongs to another
 *   vault, or does not carry a signing key.
 * @internal
 */
export function requireSigningCapabilityClaims(
  token: CapabilityToken,
  owner: symbol,
): SigningClaims {
  const entry = requireCapabilityEntry(token, owner)
  if (entry.kind !== 'signing' || !isSigningClaims(entry.claims)) {
    throw new AuthorizationDeniedError(
      'sign() requires a signing-key capability token from authorizeSigningKey() — ' +
        'an ordinary secret token cannot be used to sign.',
    )
  }
  return entry.claims
}

/**
 * Narrow stored claims to {@link SigningClaims}.
 *
 * This guards a security discriminator, so it validates the full invariants
 * rather than trusting the shape: the `keyType` must be exactly
 * `'signing-key'`, `kid` and `backendRef` must be present non-empty strings,
 * and — defense in depth — the claims must carry no `val` field. A claims
 * object that presents both the signing markers and secret material (`val`) is
 * malformed or hostile and is rejected outright rather than treated as a
 * signing key.
 *
 * @internal
 */
export function isSigningClaims(claims: StoredClaims): claims is SigningClaims {
  // Inspect via an index-signature view so each check is a real runtime
  // validation, not a type-level tautology over the pre-narrowed union.
  const record: Record<string, unknown> = { ...claims }
  const kid = record.kid
  const backendRef = record.backendRef
  return (
    record.keyType === 'signing-key' &&
    typeof kid === 'string' &&
    kid.length > 0 &&
    typeof backendRef === 'string' &&
    backendRef.length > 0 &&
    !('val' in record)
  )
}
