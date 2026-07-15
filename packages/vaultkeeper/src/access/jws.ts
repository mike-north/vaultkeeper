/**
 * Detached-payload Compact JWS assembly and verification.
 *
 * The signature format is the documented, stable contract for `sign`/`verify`:
 * a detached-payload Compact JWS (RFC 7515 §7.2.2 + RFC 7797 `b64:false`,
 * `crit:["b64"]`). The serialization is `<protected>..<signature>` with the
 * payload omitted; the algorithm is `EdDSA` (Ed25519); all encoding is
 * base64url without padding. The output is byte-for-byte what `jose`'s
 * `CompactSign` produces for the same header and payload, so any standards
 * compliant JOSE library verifies it independently.
 *
 * Signing is performed by a caller-supplied signer so the private key can stay
 * inside the backend — this module never sees key material during signing.
 *
 * @see https://www.rfc-editor.org/rfc/rfc7515 (JWS)
 * @see https://www.rfc-editor.org/rfc/rfc7797 (Unencoded Payload Option)
 * @internal
 */

import { Buffer } from 'node:buffer'
import { flattenedVerify, importSPKI } from 'jose'
import type { VerifyRequest } from '../types.js'
import { InvalidKeyMaterialError } from '../errors.js'

/** The single supported JWS `alg` (Ed25519). */
export const JWS_ALG = 'EdDSA'

/** Coerce a string|Buffer payload to raw bytes (strings are UTF-8). */
function toBytes(data: string | Buffer): Buffer {
  return Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf8')
}

/**
 * Build the RFC 7797 (`b64:false`) JWS Signing Input:
 * `ASCII(BASE64URL(UTF8(protected)) || '.') || payload`.
 */
function signingInput(protectedB64: string, payload: Buffer): Buffer {
  return Buffer.concat([Buffer.from(`${protectedB64}.`, 'ascii'), payload])
}

/**
 * Assemble a detached-payload Compact JWS over `payload`, delegating the raw
 * signature to `sign` (which the backend performs so the key never leaves it).
 *
 * @param kid - Stable key identifier placed in the protected header.
 * @param payload - The detached payload bytes.
 * @param sign - Signer that returns the raw Ed25519 signature over its input.
 * @returns The compact serialization `<protected>..<signature>`.
 * @internal
 */
export async function createDetachedJws(
  kid: string,
  payload: string | Buffer,
  sign: (data: Buffer) => Promise<Buffer>,
): Promise<string> {
  const header = { alg: JWS_ALG, b64: false, crit: ['b64'], kid }
  const protectedB64 = Buffer.from(JSON.stringify(header), 'utf8').toString('base64url')
  const signature = await sign(signingInput(protectedB64, toBytes(payload)))
  return `${protectedB64}..${signature.toString('base64url')}`
}

/**
 * Shape of the protected header we require for a valid detached JWS. Anything
 * that does not match is treated as a non-verifying signature (not an error).
 *
 * Per RFC 7515 §4.1.11, a verifier MUST reject a JWS whose `crit` lists any
 * extension it does not understand. This verifier understands only the RFC 7797
 * `b64` extension, so `crit` must be exactly `["b64"]` — a `crit` carrying any
 * additional (un-understood) parameter, e.g. `["b64","x"]`, is rejected.
 */
function hasExpectedHeader(header: unknown): boolean {
  if (typeof header !== 'object' || header === null) {
    return false
  }
  const record: Record<string, unknown> = { ...header }
  const crit = record.crit
  return (
    record.alg === JWS_ALG &&
    record.b64 === false &&
    Array.isArray(crit) &&
    crit.length === 1 &&
    crit[0] === 'b64'
  )
}

/**
 * Verify a detached-payload Compact JWS against a public key, fully offline.
 *
 * Returns `false` for a signature that does not verify — a tampered payload,
 * the wrong key, or a structurally malformed JWS. Throws
 * {@link InvalidKeyMaterialError} only when the *public key* itself is not
 * parseable (or a private key was supplied), which is an operational fault
 * rather than a bad signature.
 *
 * @internal
 */
export async function verifyDetachedJws(request: VerifyRequest): Promise<boolean> {
  // Reject a private key supplied as the public key with a clear message before
  // parsing — the documented contract is an SPKI *public* key only.
  if (request.publicKey.includes('PRIVATE KEY')) {
    throw new InvalidKeyMaterialError(
      'A private key was supplied where an SPKI public key is required.',
    )
  }

  // Strictly parse the input as an SPKI PEM public key for the EdDSA algorithm.
  // Unlike crypto.createPublicKey(), which accepts a range of PEM/DER encodings
  // (PKCS#1, certificates, other curves), importSPKI enforces the exact
  // documented contract: anything that is not an SPKI PEM EdDSA public key —
  // PKCS#1, a wrong-curve/RSA SPKI, or garbage — throws, and we surface it as a
  // typed InvalidKeyMaterialError (an operational fault, not a bad signature).
  let key: Awaited<ReturnType<typeof importSPKI>>
  try {
    key = await importSPKI(request.publicKey, JWS_ALG)
  } catch {
    throw new InvalidKeyMaterialError(
      'The supplied public key is not an SPKI PEM EdDSA public key.',
    )
  }

  const parts = request.jws.trim().split('.')
  if (parts.length !== 3) {
    return false
  }
  const [protectedB64, middle, signatureB64] = parts
  // A detached compact JWS has an empty payload segment.
  if (protectedB64 === undefined || signatureB64 === undefined || middle !== '') {
    return false
  }

  let header: unknown
  try {
    header = JSON.parse(Buffer.from(protectedB64, 'base64url').toString('utf8'))
  } catch {
    return false
  }
  if (!hasExpectedHeader(header)) {
    return false
  }

  try {
    await flattenedVerify(
      { protected: protectedB64, payload: toBytes(request.payload), signature: signatureB64 },
      key,
      { algorithms: [JWS_ALG] },
    )
    return true
  } catch {
    return false
  }
}
