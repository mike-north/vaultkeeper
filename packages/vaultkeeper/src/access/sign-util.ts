/**
 * Shared algorithm resolution for signing and verification.
 * @internal
 */

import type { KeyObject } from 'node:crypto'
import { InvalidAlgorithmError } from '../errors.js'

/**
 * Allowlist of hash algorithms accepted for non-Edwards keys.
 * Prevents algorithm downgrade attacks (e.g. callers requesting `'md5'`).
 * @internal
 */
const ALLOWED_ALGORITHMS = new Set(['sha256', 'sha384', 'sha512'])

/**
 * Resolve the algorithm parameter for `crypto.sign()` / `crypto.verify()`
 * based on the key type.
 *
 * Ed25519 / Ed448 keys use `null` (the algorithm is implicit in the key).
 * RSA and EC keys default to `'sha256'` unless overridden.
 *
 * @param key - The key object to inspect
 * @param override - Caller-provided algorithm override (ignored for Edwards curves)
 * @returns `signAlg` is passed to the Node.js crypto API; `label` is the
 *   human-readable algorithm name returned to the caller.
 * @throws {InvalidAlgorithmError} If `override` is not in the allowed algorithm set.
 * @internal
 */
export function resolveAlgorithmForKey(
  key: KeyObject,
  override: string | undefined,
): { signAlg: string | null; label: string } {
  const keyType = key.asymmetricKeyType
  if (keyType === 'ed25519' || keyType === 'ed448') {
    return { signAlg: null, label: keyType }
  }
  const alg = (override ?? 'sha256').toLowerCase()
  if (!ALLOWED_ALGORITHMS.has(alg)) {
    throw new InvalidAlgorithmError(
      `Unsupported algorithm '${alg}'. Allowed: ${[...ALLOWED_ALGORITHMS].join(', ')}`,
      alg,
      [...ALLOWED_ALGORITHMS],
    )
  }
  return { signAlg: alg, label: alg }
}
