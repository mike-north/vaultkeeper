/**
 * JWE token layer barrel export.
 */

export { createToken, decryptToken, extractKid } from './token.js'
export type { CreateTokenOptions } from './token.js'

export { validateClaims, blockToken, isBlocked, clearBlocklist } from './claims.js'

export type { VaultJWEHeader, VaultClaims } from './types.js'
