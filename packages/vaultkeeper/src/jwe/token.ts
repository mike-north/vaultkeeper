/**
 * JWE token creation and decryption using `jose` with `dir` + `A256GCM`.
 */

import { CompactEncrypt, compactDecrypt } from 'jose'
import type { VaultClaims } from '../types.js'
import { VaultError } from '../errors.js'

const ALGORITHM = 'dir'
const ENCRYPTION = 'A256GCM'

/**
 * Options for token creation.
 * @internal
 */
export interface CreateTokenOptions {
  /** Optional key ID to embed in the JWE header for rotation tracking. */
  kid?: string | undefined
}

/**
 * Creates a compact JWE string from the given claims.
 *
 * Uses `dir` (direct key agreement) with `A256GCM` content encryption.
 * The 256-bit key must be exactly 32 bytes.
 *
 * @param key - 32-byte symmetric key (AES-256)
 * @param claims - VaultClaims payload to encrypt
 * @param options - Optional token creation options
 * @returns Compact JWE string
 * @internal
 */
export async function createToken(
  key: Uint8Array,
  claims: VaultClaims,
  options?: CreateTokenOptions,
): Promise<string> {
  const plaintext = new TextEncoder().encode(JSON.stringify(claims))

  const header: { alg: typeof ALGORITHM; enc: typeof ENCRYPTION; kid?: string } = {
    alg: ALGORITHM,
    enc: ENCRYPTION,
  }

  if (options?.kid !== undefined) {
    header.kid = options.kid
  }

  return new CompactEncrypt(plaintext).setProtectedHeader(header).encrypt(key)
}

/**
 * Type guard that checks whether an unknown value is a non-null object.
 */
function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

/**
 * Parses a raw JSON payload object into VaultClaims, validating that all required fields
 * are present and of the correct types. Returns `undefined` if validation fails.
 */
function parseVaultClaims(raw: unknown): VaultClaims | undefined {
  if (!isObject(raw)) {
    return undefined
  }

  const { jti, exp, iat, sub, exe, use, tid, bkd, val, ref } = raw

  if (typeof jti !== 'string') return undefined
  if (typeof exp !== 'number') return undefined
  if (typeof iat !== 'number') return undefined
  if (typeof sub !== 'string') return undefined
  if (typeof exe !== 'string') return undefined
  if (use !== null && typeof use !== 'number') return undefined
  if (tid !== 1 && tid !== 2 && tid !== 3) return undefined
  if (typeof bkd !== 'string') return undefined
  if (typeof val !== 'string') return undefined
  if (typeof ref !== 'string') return undefined

  return { jti, exp, iat, sub, exe, use: use ?? null, tid, bkd, val, ref }
}

/**
 * Decrypts a compact JWE string and returns the VaultClaims payload.
 *
 * @param key - 32-byte symmetric key (AES-256)
 * @param jwe - Compact JWE string to decrypt
 * @returns Decrypted VaultClaims
 * @throws VaultError if decryption fails or the payload is malformed
 * @internal
 */
export async function decryptToken(key: Uint8Array, jwe: string): Promise<VaultClaims> {
  let plaintext: Uint8Array
  try {
    const result = await compactDecrypt(jwe, key)
    plaintext = result.plaintext
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err)
    throw new VaultError(`JWE decryption failed: ${message}`)
  }

  let parsed: unknown
  try {
    parsed = JSON.parse(new TextDecoder().decode(plaintext))
  } catch {
    throw new VaultError('JWE payload is not valid JSON')
  }

  const claims = parseVaultClaims(parsed)
  if (claims === undefined) {
    throw new VaultError('JWE payload does not match VaultClaims schema')
  }

  return claims
}

/**
 * Extracts the `kid` header from a compact JWE without decrypting it.
 *
 * The protected header in compact JWE is the first Base64URL-encoded segment.
 *
 * @param jwe - Compact JWE string
 * @returns The kid value, or undefined if not present
 * @throws VaultError if the JWE structure is invalid
 * @internal
 */
export function extractKid(jwe: string): string | undefined {
  const parts = jwe.split('.')
  if (parts.length !== 5) {
    throw new VaultError('Invalid JWE compact serialization: expected 5 parts')
  }
  const headerSegment = parts[0]
  if (headerSegment === undefined || headerSegment === '') {
    throw new VaultError('Invalid JWE compact serialization: missing header segment')
  }
  let headerJson: string
  try {
    headerJson = Buffer.from(headerSegment, 'base64url').toString('utf-8')
  } catch {
    throw new VaultError('Invalid JWE compact serialization: header is not valid Base64URL')
  }

  let header: unknown
  try {
    header = JSON.parse(headerJson)
  } catch {
    throw new VaultError('Invalid JWE compact serialization: header is not valid JSON')
  }

  if (!isObject(header)) {
    return undefined
  }

  const kid = header.kid
  if (typeof kid !== 'string') {
    return undefined
  }
  return kid
}
