/**
 * Delegated signing access pattern.
 *
 * Receives a PEM-encoded private key from VaultKeeper internals,
 * creates a signature over the provided data, and returns the
 * base64-encoded signature. The private key never leaves this module.
 */

import * as crypto from 'node:crypto'
import type { SignRequest, SignResult } from '../types.js'
import { resolveAlgorithmForKey } from './sign-util.js'

/**
 * Sign data using a PEM-encoded private key.
 *
 * @param secretPem - PEM-encoded private key (from `claims.val`)
 * @param request - The sign request (data + optional algorithm override)
 * @returns Base64-encoded signature and the algorithm used
 * @internal
 */
export function delegatedSign(
  secretPem: string,
  request: SignRequest,
): SignResult {
  // Note: `secretPem` is a JS string and cannot be zeroed. This is consistent
  // with how `delegatedFetch` and `delegatedExec` handle `claims.val`. Node.js
  // `KeyObject` also does not expose a zeroing API.
  const key = crypto.createPrivateKey(secretPem)
  const { signAlg, label } = resolveAlgorithmForKey(key, request.algorithm)

  const signature = crypto.sign(signAlg, Buffer.from(request.data), key)

  return {
    signature: signature.toString('base64'),
    algorithm: label,
  }
}
