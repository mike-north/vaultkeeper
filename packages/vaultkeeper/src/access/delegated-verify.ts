/**
 * Delegated verification utility.
 *
 * Verifies a signature against public key material. This is a static
 * utility — no secrets are involved, so it does not require a VaultKeeper
 * instance or capability token.
 */

import * as crypto from 'node:crypto'
import type { VerifyRequest } from '../types.js'
import { assertAllowedAlgorithm, resolveAlgorithmForKey } from './sign-util.js'

/**
 * Verify a signature using a public key.
 *
 * Returns `false` for invalid key material, malformed signatures, or any
 * verification failure. The one exception is disallowed algorithms (e.g.
 * `'md5'`, `'sha1'`), which throw {@link InvalidAlgorithmError} so that
 * callers cannot silently downgrade to a weak hash.
 *
 * @param request - The verify request (data, signature, publicKey, optional algorithm)
 * @returns `true` if the signature is valid, `false` otherwise
 * @throws {InvalidAlgorithmError} If `request.algorithm` is not in the allowed set.
 * @internal
 */
export function delegatedVerify(request: VerifyRequest): boolean {
  // A disallowed algorithm (e.g. 'md5') is a downgrade attempt and must throw
  // InvalidAlgorithmError unconditionally — including when the public key is
  // also malformed or attacker-controlled. This guard therefore runs BEFORE
  // parsing the key: parsing first would short-circuit to `return false` on a
  // bad key and silently skip the algorithm check (see issue #180).
  assertAllowedAlgorithm(request.algorithm)

  // Invalid key material or malformed signatures are treated as verification
  // failures (return false) rather than thrown errors. Disallowed algorithms
  // are the deliberate exception — already rejected above.
  let key: crypto.KeyObject
  try {
    key = crypto.createPublicKey(request.publicKey)
  } catch {
    return false
  }

  // Reject private key material passed as publicKey — crypto.createPublicKey()
  // silently derives the public component from a private key PEM, which could
  // mask a consumer misconfiguration. We check the raw PEM text because
  // createPublicKey() converts private keys to public KeyObjects transparently.
  if (typeof request.publicKey === 'string' && request.publicKey.includes('PRIVATE KEY')) {
    return false
  }

  // NOTE: resolveAlgorithmForKey throws for disallowed algorithms (e.g. 'md5').
  // That error must propagate — do NOT wrap this call in a try/catch.
  const { signAlg } = resolveAlgorithmForKey(key, request.algorithm)
  const sig = Buffer.from(request.signature, 'base64')

  try {
    const data = Buffer.isBuffer(request.data)
      ? request.data
      : Buffer.from(request.data)
    return crypto.verify(signAlg, data, key, sig)
  } catch {
    return false
  }
}
