/**
 * Cross-language conformance for the `validateClaims` / `validate_claims`
 * chokepoint (issue #280).
 *
 * `validateClaims` (TypeScript, `packages/vaultkeeper/src/jwe/claims.ts`) and
 * `validate_claims` (Rust, `crates/vaultkeeper-core/src/jwe/token.rs`) are the
 * single validation chokepoint every token in the system passes through, in
 * both languages. This file feeds the same malformed and well-formed claims
 * payloads to both implementations and asserts they reject/accept identically
 * and — for rejections — with byte-identical error messages, so the two
 * implementations cannot silently drift apart.
 *
 * The Rust side is exercised through `__testValidateClaims`, a
 * diagnostic-only wasm-bindgen export (`crates/vaultkeeper-wasm/src/wasm_impl.rs`)
 * that runs the real Rust core's `validate_claims` directly against a
 * caller-supplied claims payload — no JWE, key, or `VaultKeeper` instance
 * needed. This mirrors the established `__testAllVaultErrors` /
 * `error-parity.test.ts` pattern (`packages/vaultkeeper-wasm/src/test/error-parity.test.ts`)
 * for the error taxonomy at large.
 *
 * The TS side imports `validateClaims` directly from the `vaultkeeper`
 * package's source (it is `@internal` and intentionally not part of the
 * public API in `packages/vaultkeeper/src/index.ts`) — this file is the one
 * place outside that package's own test suite that needs it, specifically to
 * compare it against the Rust implementation.
 */
import { describe, it, expect, beforeAll } from 'vitest'
import * as path from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { validateClaims } from '../../../vaultkeeper/src/jwe/claims.js'
import type { VaultClaims } from '../../../vaultkeeper/src/types.js'
import { VaultError } from '../../../vaultkeeper/src/errors.js'

const __dirname = path.dirname(fileURLToPath(import.meta.url))

/** Loose shape of a value produced by the real Rust `vault_error_to_js` bridge. */
interface BridgeErrorShape {
  vaultErrorCode: string
  message: string
}

function isBridgeErrorShape(value: unknown): value is BridgeErrorShape {
  if (typeof value !== 'object' || value === null) return false
  const record: Record<string, unknown> = { ...value }
  return typeof record.vaultErrorCode === 'string' && typeof record.message === 'string'
}

type ValidateClaimsFn = (claimsJson: string, usedCount: bigint) => void

/** Narrows an unknown export to the diagnostic function's call signature, without an `as` cast. */
function isValidateClaimsFn(value: unknown): value is ValidateClaimsFn {
  return typeof value === 'function'
}

let __testValidateClaims: ValidateClaimsFn | undefined

beforeAll(async () => {
  // The committed wasm artifact (`packages/vaultkeeper-wasm/wasm/`) — same
  // binary the SDK ships — loaded directly, mirroring how
  // `error-parity.test.ts` reaches the diagnostic export.
  const wasmPath = path.join(
    __dirname,
    '..',
    '..',
    '..',
    'vaultkeeper-wasm',
    'wasm',
    'vaultkeeper_wasm.js',
  )
  const bindings: unknown = await import(pathToFileURL(wasmPath).href)
  if (typeof bindings !== 'object' || bindings === null) {
    throw new Error('committed wasm artifact did not resolve to a module object')
  }
  const record: Record<string, unknown> = { ...bindings }
  const fn = record.__testValidateClaims
  if (!isValidateClaimsFn(fn)) {
    throw new Error('__testValidateClaims export not found in the committed wasm artifact')
  }
  __testValidateClaims = fn
})

/** Builds a well-formed secret VaultClaims (TS runtime shape) for `validateClaims`. */
function makeSecretClaims(overrides: Partial<VaultClaims> = {}): VaultClaims {
  const now = Math.floor(Date.now() / 1000)
  return {
    jti: 'parity-jti-secret-1',
    exp: now + 3600,
    iat: now,
    sub: '/secrets/db-password',
    exe: 'a'.repeat(64),
    use: null,
    tid: 1,
    bkd: 'file',
    val: 'encrypted-value',
    ref: '/file/db-password',
    ...overrides,
  }
}

/** Builds a well-formed signing-key lease VaultClaims (TS runtime shape). */
function makeLeaseClaims(overrides: Partial<VaultClaims> = {}): VaultClaims {
  const now = Math.floor(Date.now() / 1000)
  return {
    jti: 'parity-jti-lease-1',
    exp: now + 3600,
    iat: now,
    sub: 'release-key',
    exe: 'a'.repeat(64),
    use: null,
    tid: 1,
    ref: 'release-key',
    kty: 'signing-key',
    kid: 'kid-abc123',
    kgen: 1,
    ...overrides,
  }
}

/**
 * Converts a TS-runtime `VaultClaims` object into the wire JSON the Rust core
 * expects. Only `tid` differs on the wire: Rust's `TrustTier` deserializes
 * from the string form (`"1"`/`"2"`/`"3"`), matching
 * `#[serde(rename_all = ...)]` in `crates/vaultkeeper-core/src/types.rs`,
 * while `validateClaims` itself performs no runtime check on `tid` — so this
 * conversion does not affect what's actually under test here.
 */
function toWireJson(claims: VaultClaims): string {
  return JSON.stringify({ ...claims, tid: String(claims.tid) })
}

/** Runs `__testValidateClaims` and returns the bridged error, or `undefined` on success. */
function runRust(claims: VaultClaims, usedCount = 0): BridgeErrorShape | undefined {
  if (__testValidateClaims === undefined) {
    throw new Error('__testValidateClaims not loaded — beforeAll did not run')
  }
  try {
    __testValidateClaims(toWireJson(claims), BigInt(usedCount))
    return undefined
  } catch (err) {
    if (!isBridgeErrorShape(err)) {
      throw new Error(`__testValidateClaims threw a non-bridge value: ${JSON.stringify(err)}`)
    }
    return err
  }
}

/** Runs TS `validateClaims` and returns its message, or `undefined` on success. */
function runTs(claims: VaultClaims, usedCount = 0): string | undefined {
  try {
    validateClaims(claims, usedCount)
    return undefined
  } catch (err) {
    expect(err).toBeInstanceOf(VaultError)
    return err instanceof Error ? err.message : String(err)
  }
}

describe('validateClaims / validate_claims cross-language parity (issue #280)', () => {
  it('both accept a well-formed secret claim', () => {
    const claims = makeSecretClaims()
    expect(runTs(claims)).toBeUndefined()
    expect(runRust(claims)).toBeUndefined()
  })

  it('both accept a well-formed signing-key lease (no val, valid kgen) — AC5', () => {
    const claims = makeLeaseClaims()
    expect(runTs(claims)).toBeUndefined()
    expect(runRust(claims)).toBeUndefined()
  })

  it('both reject a signing-key lease that carries a val — AC2', () => {
    const claims = makeLeaseClaims({ val: 'should-not-be-here' })
    const tsMessage = runTs(claims)
    const rustError = runRust(claims)
    expect(tsMessage).toBe('Invalid token: signing lease must not carry a val')
    expect(rustError?.message).toBe(tsMessage)
  })

  it('both reject a secret claim missing val — AC3', () => {
    const { val: _val, ...claims } = makeSecretClaims()
    const tsMessage = runTs(claims)
    const rustError = runRust(claims)
    expect(tsMessage).toBe('Invalid token: val must not be empty')
    expect(rustError?.message).toBe(tsMessage)
  })

  it('both reject a secret claim with an empty val — AC3', () => {
    const claims = makeSecretClaims({ val: '' })
    const tsMessage = runTs(claims)
    const rustError = runRust(claims)
    expect(tsMessage).toBe('Invalid token: val must not be empty')
    expect(rustError?.message).toBe(tsMessage)
  })

  it('both reject a secret claim with a whitespace-only val — AC3', () => {
    const claims = makeSecretClaims({ val: '   ' })
    const tsMessage = runTs(claims)
    const rustError = runRust(claims)
    expect(tsMessage).toBe('Invalid token: val must not be empty')
    expect(rustError?.message).toBe(tsMessage)
  })

  it('both reject a signing-key lease missing kgen rather than defaulting to 0 — AC4', () => {
    const { kgen: _kgen, ...claims } = makeLeaseClaims()
    const tsMessage = runTs(claims)
    const rustError = runRust(claims)
    expect(tsMessage).toBe('Invalid token: kgen is required for a signing lease')
    expect(rustError?.message).toBe(tsMessage)
  })

  it('both accept a signing-key lease with kgen explicitly 0 (never defaulted, but a valid explicit value)', () => {
    const claims = makeLeaseClaims({ kgen: 0 })
    expect(runTs(claims)).toBeUndefined()
    expect(runRust(claims)).toBeUndefined()
  })

  it('both reject a signing-key lease missing kid', () => {
    const { kid: _kid, ...claims } = makeLeaseClaims()
    const tsMessage = runTs(claims)
    const rustError = runRust(claims)
    expect(tsMessage).toBe('Invalid token: kid must not be empty')
    expect(rustError?.message).toBe(tsMessage)
  })

  it('both reject a secret claim missing bkd', () => {
    const { bkd: _bkd, ...claims } = makeSecretClaims()
    const tsMessage = runTs(claims)
    const rustError = runRust(claims)
    expect(tsMessage).toBe('Invalid token: bkd must not be empty')
    expect(rustError?.message).toBe(tsMessage)
  })

  it('both treat an omitted kty as a secret claim (legacy-token backward compatibility)', () => {
    const claims = makeSecretClaims()
    expect(claims.kty).toBeUndefined()
    expect(runTs(claims)).toBeUndefined()
    expect(runRust(claims)).toBeUndefined()
  })

  it('both reject a signing-key lease carrying an empty val — no empty-string exemption', () => {
    const claims = makeLeaseClaims({ val: '' })
    const tsMessage = runTs(claims)
    const rustError = runRust(claims)
    expect(tsMessage).toBe('Invalid token: signing lease must not carry a val')
    expect(rustError?.message).toBe(tsMessage)
  })

  it('both reject a signing-key lease carrying a whitespace-only val — no exemption', () => {
    const claims = makeLeaseClaims({ val: '   ' })
    const tsMessage = runTs(claims)
    const rustError = runRust(claims)
    expect(tsMessage).toBe('Invalid token: signing lease must not carry a val')
    expect(rustError?.message).toBe(tsMessage)
  })

  it('both reject a signing-key lease with a whitespace-only kid', () => {
    const claims = makeLeaseClaims({ kid: '   ' })
    const tsMessage = runTs(claims)
    const rustError = runRust(claims)
    expect(tsMessage).toBe('Invalid token: kid must not be empty')
    expect(rustError?.message).toBe(tsMessage)
  })

  it('both reject a secret claim carrying a signing-lease kid — cross-shape leakage', () => {
    const claims = makeSecretClaims({ kid: 'kid-should-not-be-here' })
    const tsMessage = runTs(claims)
    const rustError = runRust(claims)
    expect(tsMessage).toBe(
      'Invalid token: secret claim must not carry signing-lease fields (kid/kgen/pres)',
    )
    expect(rustError?.message).toBe(tsMessage)
  })

  it('both reject a secret claim carrying a signing-lease kgen — cross-shape leakage', () => {
    const claims = makeSecretClaims({ kgen: 1 })
    const tsMessage = runTs(claims)
    const rustError = runRust(claims)
    expect(tsMessage).toBe(
      'Invalid token: secret claim must not carry signing-lease fields (kid/kgen/pres)',
    )
    expect(rustError?.message).toBe(tsMessage)
  })

  it('both reject a secret claim carrying a signing-lease pres — cross-shape leakage', () => {
    const claims = makeSecretClaims({
      pres: { op: 'sign', at: Math.floor(Date.now() / 1000), method: 'touch', backend: 'yubikey' },
    })
    const tsMessage = runTs(claims)
    const rustError = runRust(claims)
    expect(tsMessage).toBe(
      'Invalid token: secret claim must not carry signing-lease fields (kid/kgen/pres)',
    )
    expect(rustError?.message).toBe(tsMessage)
  })

  // An unrecognized `kty` cannot be fed through `runRust`'s normal path: the
  // Rust core's `ClaimsKind` has no catch-all variant, so `serde` rejects it
  // at *deserialization* — before `validate_claims` is even reached — while
  // the TS side rejects it inside `validateClaims` itself (a defense-in-depth
  // check, since `parseVaultClaims` already rejects it earlier in the real
  // decrypt pipeline too). The two therefore cannot produce byte-identical
  // messages; this asserts outcome parity (both reject) and documents why the
  // messages differ, following this suite's established convention for that
  // case (see the header comment).
  it('both reject an unrecognized kty rather than silently treating it as a secret claim', () => {
    const claims = makeSecretClaims()
    const record: Record<string, unknown> = { ...claims, kty: 'wat' }
    if (!isRecordVaultClaimsShapedIgnoringKty(record)) {
      throw new Error('unreachable: base claims always satisfy the minimal shape')
    }

    expect(() => {
      validateClaims(record)
    }).toThrow('Invalid token: unrecognized claim kind kty=wat')

    // Rust: `serde_json::from_str::<VaultClaims>` fails outright for an
    // unknown `ClaimsKind` string — bridged as `invalid-token`, not the
    // typed validation error `validateClaims` itself would raise for a
    // recognized-but-invalid shape. The messages therefore cannot be
    // byte-identical; this asserts outcome parity (both reject) instead.
    if (__testValidateClaims === undefined) {
      throw new Error('__testValidateClaims not loaded — beforeAll did not run')
    }
    expect(() => {
      __testValidateClaims?.(JSON.stringify({ ...record, tid: String(record.tid) }), BigInt(0))
    }).toThrow()
  })

  // Same outcome-parity convention as the unrecognized-kty case above: Rust
  // deserializes `kgen` as a `u64`, so a fractional value fails in serde
  // (bridged as `invalid-token`) before `validate_claims` runs, while TS
  // rejects it inside `validateClaims` with its own typed message. Both must
  // reject — a fractional kgen accepted by TS would mint a lease the Rust
  // core can never deserialize.
  it('both reject a fractional kgen rather than minting a lease Rust cannot deserialize', () => {
    const claims = makeLeaseClaims()
    const record: Record<string, unknown> = { ...claims, kgen: 1.5 }
    if (!isRecordVaultClaimsShapedIgnoringKty(record)) {
      throw new Error('unreachable: base lease claims always satisfy the minimal shape')
    }

    expect(() => {
      validateClaims(record)
    }).toThrow('Invalid token: kgen must be a non-negative integer')

    if (__testValidateClaims === undefined) {
      throw new Error('__testValidateClaims not loaded — beforeAll did not run')
    }
    expect(() => {
      __testValidateClaims?.(JSON.stringify({ ...record, tid: String(record.tid) }), BigInt(0))
    }).toThrow()
  })
})

/**
 * Type predicate used only to build a deliberately malformed claims payload
 * (an unrecognized `kty`) for testing `validateClaims`'s own defense-in-depth
 * rejection. The real decrypt pipeline's `parseVaultClaims`
 * (`packages/vaultkeeper/src/jwe/token.ts`) already rejects this earlier and
 * is not exercised by this path — this validates only the minimal shape
 * `validateClaims` itself relies on, treating `kty` as an arbitrary string
 * rather than requiring it to be a known `ClaimsKind`.
 */
function isRecordVaultClaimsShapedIgnoringKty(value: unknown): value is VaultClaims {
  if (typeof value !== 'object' || value === null) return false
  const record: Record<string, unknown> = { ...value }
  return (
    typeof record.jti === 'string' &&
    typeof record.exp === 'number' &&
    typeof record.iat === 'number' &&
    typeof record.sub === 'string' &&
    typeof record.exe === 'string' &&
    typeof record.ref === 'string'
  )
}
