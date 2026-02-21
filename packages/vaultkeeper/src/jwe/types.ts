/**
 * JWE-specific types for vaultkeeper token layer.
 */

import type { VaultClaims } from '../types.js'

/**
 * JWE protected header parameters used for vaultkeeper tokens.
 * Extends the standard `dir` + `A256GCM` algorithm with a `kid` for key rotation.
 */
export interface VaultJWEHeader {
  /** Key Agreement algorithm — always "dir" (direct key agreement) */
  alg: 'dir'
  /** Content Encryption algorithm — always "A256GCM" */
  enc: 'A256GCM'
  /** Key ID for rotation tracking */
  kid?: string | undefined
}

/**
 * Re-export VaultClaims from the shared types for consumers who only import from jwe.
 */
export type { VaultClaims }
