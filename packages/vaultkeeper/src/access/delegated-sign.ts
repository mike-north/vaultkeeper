/**
 * Delegated signing access pattern.
 *
 * Receives a PEM-encoded private key from VaultKeeper internals,
 * creates a signature over the provided data, and returns the
 * base64-encoded signature. The key is not exposed to the caller —
 * it flows in but does not flow out.
 */

import * as crypto from 'node:crypto'
import type { SignRequest, SignResult } from '../types.js'
import { InvalidKeyMaterialError } from '../errors.js'
import { resolveAlgorithmForKey } from './sign-util.js'

/**
 * Sign data using a PEM-encoded private key.
 *
 * @param secretPem - PEM-encoded private key (from `claims.val`)
 * @param request - The sign request (data + optional algorithm override)
 * @returns Base64-encoded signature and the algorithm used
 * @throws {InvalidKeyMaterialError} If `secretPem` is not valid PEM/DER
 *   private key material.
 * @internal
 */
export function delegatedSign(secretPem: string, request: SignRequest): SignResult {
  // Note: `secretPem` is a JS string and cannot be zeroed. This is consistent
  // with how `delegatedFetch` and `delegatedExec` handle `claims.val`. Node.js
  // `KeyObject` also does not expose a zeroing API.
  let key: crypto.KeyObject
  try {
    key = crypto.createPrivateKey(secretPem)
  } catch {
    // Never include `secretPem` (or the underlying OpenSSL error, which can
    // echo fragments of the input) in the thrown message.
    throw new InvalidKeyMaterialError(
      'The stored secret is not valid PEM/DER private key material. ' +
        'delegatedSign() requires a secret that was stored as a private key.',
    )
  }
  const { signAlg, label } = resolveAlgorithmForKey(key, request.algorithm)

  const data = Buffer.isBuffer(request.data) ? request.data : Buffer.from(request.data)
  const signature = crypto.sign(signAlg, data, key)

  return {
    signature: signature.toString('base64'),
    algorithm: label,
  }
}
