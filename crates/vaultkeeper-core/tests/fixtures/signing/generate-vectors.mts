/**
 * Generates the fixed Ed25519 test keypair and golden detached-JWS vectors
 * consumed by the Rust core's byte-exact wire-compatibility tests
 * (`crates/vaultkeeper-core/src/signing/jws.rs`) and by the JS conformance
 * runner's cross-verification cases (issue #237, AC4).
 *
 * This runs the REAL production TypeScript module
 * (`packages/vaultkeeper/src/access/jws.ts`) to produce and verify every
 * vector, so the committed `vectors.json` is not a hand-rolled
 * re-implementation of the JWS contract — it is the actual shipped
 * `createDetachedJws`/`verifyDetachedJws` output. `verifyDetachedJws`
 * internally uses `jose` (`flattenedVerify`/`importSPKI`), so every vector is
 * genuinely jose-verified before being committed.
 *
 * Key generation and raw Ed25519 signing use Node's built-in `node:crypto`
 * (not the `jose` high-level envelope APIs, which do not expose a raw
 * detached-signing primitive) — this is the same underlying engine `jose`
 * itself delegates to for asymmetric operations on Node.
 *
 * Usage (regenerates `vectors.json`; reuses the committed keypair if present
 * so vectors stay reproducible — delete the `.pem` files to force a fresh
 * fixed keypair):
 *
 *   pnpm exec tsx crates/vaultkeeper-core/tests/fixtures/signing/generate-vectors.mts
 *
 * @see https://www.rfc-editor.org/rfc/rfc7515#section-7.2.2 (RFC 7515 §7.2.2 detached-payload Compact JWS)
 * @see https://www.rfc-editor.org/rfc/rfc7797 (RFC 7797 `b64:false` unencoded payload option)
 * @see https://www.rfc-editor.org/rfc/rfc8032 (RFC 8032 EdDSA / Ed25519)
 */
import { createHash, createPublicKey, generateKeyPairSync, sign as cryptoSign } from 'node:crypto'
import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { createDetachedJws, verifyDetachedJws } from '../../../../../packages/vaultkeeper/src/access/jws.js'

const here = dirname(fileURLToPath(import.meta.url))
const privateKeyPath = join(here, 'ed25519-test-key.pkcs8.pem')
const publicKeyPath = join(here, 'ed25519-test-key.spki.pem')
const vectorsPath = join(here, 'vectors.json')

/**
 * Compute the stable `kid` for an SPKI-DER public key: `base64url(sha256(der))`.
 *
 * Mirrors `computeKid` in `packages/vaultkeeper/src/backend/file-backend.ts`
 * exactly — `kid` is always derived from the public key material, never an
 * arbitrary caller-chosen label, so a golden vector's `kid` genuinely
 * exercises kid derivation rather than masking it.
 */
function computeKid(spkiDer: Buffer): string {
  return createHash('sha256').update(spkiDer).digest('base64url')
}

interface TestPayload {
  name: string
  bytes: Uint8Array
}

const payloads: TestPayload[] = [
  { name: 'empty', bytes: new Uint8Array(0) },
  { name: 'ascii', bytes: Buffer.from('hello vaultkeeper', 'utf8') },
  { name: 'utf8-multibyte', bytes: Buffer.from('héllo 世界 🔐 café', 'utf8') },
  {
    name: 'binary',
    bytes: Uint8Array.from([0x00, 0x01, 0x02, 0x7f, 0x80, 0xfe, 0xff, 0xde, 0xad, 0xbe, 0xef]),
  },
]

function loadOrCreateKeypair(): { privateKeyPem: string; publicKeyPem: string } {
  if (existsSync(privateKeyPath) && existsSync(publicKeyPath)) {
    return {
      privateKeyPem: readFileSync(privateKeyPath, 'utf8'),
      publicKeyPem: readFileSync(publicKeyPath, 'utf8'),
    }
  }
  const { privateKey, publicKey } = generateKeyPairSync('ed25519')
  const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString()
  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }).toString()
  writeFileSync(privateKeyPath, privateKeyPem)
  writeFileSync(publicKeyPath, publicKeyPem)
  return { privateKeyPem, publicKeyPem }
}

interface Vector {
  name: string
  kid: string
  payloadBase64: string
  jws: string
}

async function main(): Promise<void> {
  const { privateKeyPem, publicKeyPem } = loadOrCreateKeypair()

  const spkiDer = createPublicKey(publicKeyPem).export({ type: 'spki', format: 'der' })
  const kid = computeKid(spkiDer)

  const vectors: Vector[] = []
  for (const { name, bytes } of payloads) {
    const payload = Buffer.from(bytes)
    const jws = await createDetachedJws(kid, payload, (data) =>
      Promise.resolve(cryptoSign(null, data, privateKeyPem)),
    )

    // Sanity check every vector round-trips through the real verifier
    // (jose-backed) before committing it — a vector that doesn't verify is a
    // bug in this generator, not a valid golden vector.
    const verified = await verifyDetachedJws({ payload, jws, publicKey: publicKeyPem })
    if (!verified) {
      throw new Error(`generated vector "${name}" failed to verify — refusing to commit it`)
    }

    vectors.push({ name, kid, payloadBase64: payload.toString('base64'), jws })
  }

  writeFileSync(vectorsPath, `${JSON.stringify({ kid, vectors }, null, 2)}\n`)
  console.log(`Wrote ${vectors.length} vectors to ${vectorsPath}`)
}

await main()
