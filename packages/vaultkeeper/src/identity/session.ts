/**
 * Capability token management.
 *
 * The module-private `WeakMap` binds each token to its claims and issuer for
 * its lifetime. The token object exposes neither, and claim lookup requires
 * the issuing vault's private identity.
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

/** Claims paired with the unique identity of the vault authorized to resolve them. */
interface StoredCapability {
  readonly claims: StoredClaims
  readonly owner: symbol
}

/** Token identity controls the lifetime of the private authorization record. */
const claimsStore = new WeakMap<CapabilityToken, StoredCapability>()

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
  claimsStore.set(token, { claims, owner })
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
  claimsStore.set(token, { claims, owner })
  return token
}

/**
 * Retrieve the claims only after matching the token to the consuming vault.
 *
 * @param token - The opaque capability presented for use.
 * @param owner - The consuming vault's private identity.
 * @throws {AuthorizationDeniedError} If the token has no claims entry or its
 *   issuer differs from the consuming vault.
 * @internal
 */
export function validateCapabilityToken(token: CapabilityToken, owner: symbol): StoredClaims {
  const stored = claimsStore.get(token)
  if (stored === undefined) {
    throw new AuthorizationDeniedError('Invalid or unrecognized capability token')
  }
  if (stored.owner !== owner) {
    throw new AuthorizationDeniedError('Capability token was issued by another vault instance')
  }
  return stored.claims
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
