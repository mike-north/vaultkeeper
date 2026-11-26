/**
 * Capability token management.
 *
 * Tokens are backed by a `WeakMap` whose keys are `CapabilityToken` instances,
 * so the actual claims are never reachable from outside this module. Private
 * class fields enforce that no property on the token object leaks data.
 */

import type { VaultClaims, SigningClaims } from './types.js'
import { AuthorizationDeniedError } from '../errors.js'

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
 * An opaque handle to authorized secret claims.
 *
 * A `CapabilityToken` is produced by {@link VaultKeeper.authorize} and
 * deliberately exposes no readable data. The underlying claims — including the
 * secret value — are held in a module-private `WeakMap` that this class does
 * not reference, and its private fields keep any property from leaking them
 * (`toString()` returns only a debug identifier). There is intentionally no
 * public API for reading the claims directly.
 *
 * To use the secret, pass the token to a {@link VaultKeeper} access method —
 * {@link VaultKeeper.getSecret}, {@link VaultKeeper.fetch},
 * {@link VaultKeeper.exec}, or {@link VaultKeeper.sign} — which resolve the
 * claims internally.
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

/** Internal storage for claims — inaccessible outside the module closure. */
const claimsStore = new WeakMap<CapabilityToken, StoredClaims>()

/**
 * Create a capability token that wraps secret `claims`.
 * The claims are stored in a module-private `WeakMap` and cannot be reached
 * without calling `validateCapabilityToken`.
 * @internal
 */
export function createCapabilityToken(claims: VaultClaims): CapabilityToken {
  const token = new CapabilityToken()
  claimsStore.set(token, claims)
  return token
}

/**
 * Create a capability token that wraps signing-key `claims`.
 *
 * The claims carry only references (`kid`, `backendRef`, `keyType`) — never any
 * private key material — so a signing token can never leak a key even if the
 * WeakMap entry were somehow observed.
 * @internal
 */
export function createSigningCapabilityToken(claims: SigningClaims): CapabilityToken {
  const token = new CapabilityToken()
  claimsStore.set(token, claims)
  return token
}

/**
 * Retrieve the claims associated with `token`.
 *
 * @throws {AuthorizationDeniedError} if the token was not created by this
 *   module (i.e. it has no claims entry in the store).
 * @internal
 */
export function validateCapabilityToken(token: CapabilityToken): StoredClaims {
  const claims = claimsStore.get(token)
  if (claims === undefined) {
    throw new AuthorizationDeniedError('Invalid or unrecognized capability token')
  }
  return claims
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
