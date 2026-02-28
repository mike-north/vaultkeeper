/**
 * Delegated verification utility.
 *
 * Verifies a signature against public key material. This is a static
 * utility — no secrets are involved, so it does not require a VaultKeeper
 * instance or capability token.
 */

import * as crypto from 'node:crypto'
import type { VerifyRequest } from '../types.js'
import { resolveAlgorithmForKey } from './sign-util.js'

/**
 * Verify a signature using a public key.
 *
 * @param request - The verify request (data, signature, publicKey, optional algorithm)
 * @returns `true` if the signature is valid, `false` otherwise
 * @internal
 */
export function delegatedVerify(request: VerifyRequest): boolean {
  // Invalid key material or malformed signatures are treated as verification
  // failures (return false) rather than thrown errors. This provides a uniform
  // boolean return contract — callers can trust that `true` means "valid" and
  // `false` means "not valid for any reason" without needing error handling.
  let key: crypto.KeyObject
  try {
    key = crypto.createPublicKey(request.publicKey)
  } catch {
    return false
  }

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
