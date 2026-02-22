/**
 * Capability token management.
 *
 * Tokens are backed by a `WeakMap` whose keys are `CapabilityToken` instances,
 * so the actual claims are never reachable from outside this module. Private
 * class fields enforce that no property on the token object leaks data.
 */

import type { VaultClaims } from './types.js'
import { AuthorizationDeniedError } from '../errors.js'

/** Opaque capability token. Claims are inaccessible without `validateCapabilityToken`. */
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
const claimsStore = new WeakMap<CapabilityToken, VaultClaims>()

/**
 * Create a capability token that wraps `claims`.
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
 * Retrieve the `VaultClaims` associated with `token`.
 *
 * @throws {AuthorizationDeniedError} if the token was not created by
 *   `createCapabilityToken` in this module (i.e. it has no claims entry
 *   in the store).
 * @internal
 */
export function validateCapabilityToken(token: CapabilityToken): VaultClaims {
  const claims = claimsStore.get(token)
  if (claims === undefined) {
    throw new AuthorizationDeniedError('Invalid or unrecognized capability token')
  }
  return claims
}
