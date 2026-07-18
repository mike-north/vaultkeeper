/**
 * Error-taxonomy parity test (issue #236).
 *
 * `ALL_VAULT_ERROR_CODES` (in `../errors.js`) is the TypeScript half of the
 * single source of truth for the error taxonomy that crosses the WASM
 * boundary; the Rust half is `ALL_ERROR_CODES`
 * (`crates/vaultkeeper-core/src/errors.rs`). This test proves both directions
 * of that contract against the real compiled WASM binary rather than a
 * guessed-at boundary shape:
 *
 * 1. The exact set of codes fetched from the binary via the diagnostic export
 *    `allVaultErrorCodes()` must equal `ALL_VAULT_ERROR_CODES` exactly — no
 *    code missing on either side, no stray extra code on either side.
 * 2. For every code, a *real* `VaultError` is constructed on the Rust side and
 *    converted through the real `vault_error_to_js` bridge (via the
 *    diagnostic export `__testAllVaultErrors()`), not synthesized in
 *    TypeScript — then run through `mapWasmError()` and asserted to produce
 *    the correct typed subclass with the correct field values.
 *
 * `allVaultErrorCodes()` and `__testAllVaultErrors()` are diagnostic-only
 * exports (see `crates/vaultkeeper-wasm/src/wasm_impl.rs`) — not part of the
 * SDK's public API (`../index.ts` does not re-export them) — that exist
 * solely to drive this test. The fixture values they construct are defined
 * once, in `all_variants_for_parity_test()`
 * (`crates/vaultkeeper-core/src/errors.rs`); the expectations below must be
 * kept in sync with that function.
 *
 * Uses node:test (not vitest) since this package compiles with plain tsc,
 * matching the rest of this package's test suite.
 */

/* eslint-disable @typescript-eslint/no-floating-promises -- node:test it() returns Promise but is not meant to be awaited inside describe() */
/* eslint-disable n/no-unsupported-features/node-builtins -- test.describe is stable in our CI Node version */

import { describe, it } from 'node:test'
import * as assert from 'node:assert/strict'
import {
  mapWasmError,
  ALL_VAULT_ERROR_CODES,
  VaultError,
  SecretNotFoundError,
  DecryptionError,
  TokenExpiredError,
  KeyRotatedError,
  KeyRevokedError,
  TokenRevokedError,
  UsageLimitExceededError,
  RotationInProgressError,
  BackendLockedError,
  DeviceNotPresentError,
  AuthorizationDeniedError,
  BackendUnavailableError,
  PluginNotFoundError,
  IdentityMismatchError,
  ExecutableTrustRequiredError,
  InvalidAlgorithmError,
  SetupError,
  FilesystemError,
  NotCapableError,
  PresenceDeclinedError,
  PresenceTimeoutError,
  InvalidKeyMaterialError,
  SigningKeyNotFoundError,
  SigningKeyAlreadyExistsError,
  SigningNotSupportedError,
  ExecError,
  FetchError,
  InvalidTokenError,
  AccessorConsumedError,
  ConfigValidationError,
  UnknownBackendTypeError,
  ConfigParseError,
} from '../errors.js'

/** Loose shape of a value produced by the real `vault_error_to_js` bridge. */
interface BridgeErrorShape {
  vaultErrorCode: string
  message: string
}

/**
 * Narrows an `unknown` entry from `__testAllVaultErrors()` to
 * {@link BridgeErrorShape}, mirroring `isWasmErrorShape` in `../errors.ts`
 * (object-spread to a `Record<string, unknown>` avoids an `as` cast).
 */
function isBridgeErrorShape(value: unknown): value is BridgeErrorShape {
  if (typeof value !== 'object' || value === null) return false
  const record: Record<string, unknown> = { ...value }
  return typeof record.vaultErrorCode === 'string' && typeof record.message === 'string'
}

/**
 * Assertion-function form of an `instanceof` check: narrows `err` to `T` in
 * the caller's scope without an `as` cast (`assert.ok` alone does not narrow,
 * since node:assert's signature is a generic truthy assertion).
 *
 * `ctor`'s parameter list is deliberately `never[]`, not `unknown[]`: `ctor`
 * is only ever used for `instanceof`, never actually constructed, so any
 * class should be assignable here regardless of its real constructor
 * signature (every error class here takes at least a `message: string`).
 * Construct-signature parameters are checked contravariantly, so `unknown[]`
 * does **not** work — `unknown` is not assignable to `string`, so e.g.
 * `SecretNotFoundError`'s `(message: string)` constructor would fail to
 * satisfy `new (...args: unknown[]) => T`. `never` is assignable to every
 * type, satisfying that contravariant check vacuously for any real
 * constructor's parameter types.
 */
function assertInstance<T extends VaultError>(
  err: VaultError,
  ctor: new (...args: never[]) => T,
  code: string,
): asserts err is T {
  assert.ok(
    err instanceof ctor,
    `expected ${code} to reconstruct as ${ctor.name}, got ${err.constructor.name}`,
  )
}

async function loadDiagnosticBindings(): Promise<{
  allVaultErrorCodes: () => string[]
  __testAllVaultErrors: () => unknown[]
}> {
  // Diagnostic-only exports, deliberately not re-exported from ../index.ts —
  // imported directly from the raw wasm-bindgen glue, mirroring how
  // ../index.ts itself lazy-loads the module.
  return import('../../wasm/vaultkeeper_wasm.js')
}

describe('error-taxonomy parity (issue #236)', () => {
  it("the WASM binary's code list equals ALL_VAULT_ERROR_CODES exactly", async () => {
    const bindings = await loadDiagnosticBindings()
    const wasmCodes = [...bindings.allVaultErrorCodes()].sort()
    const tsCodes = [...ALL_VAULT_ERROR_CODES].sort()
    assert.deepEqual(
      wasmCodes,
      tsCodes,
      'ALL_ERROR_CODES (Rust) and ALL_VAULT_ERROR_CODES (TS) have drifted apart',
    )
  })

  it('every code in ALL_VAULT_ERROR_CODES is unique', () => {
    const unique = new Set(ALL_VAULT_ERROR_CODES)
    assert.equal(unique.size, ALL_VAULT_ERROR_CODES.length)
  })

  it('round-trips every real bridge-produced error to the correct typed subclass with correct fields', async () => {
    const bindings = await loadDiagnosticBindings()
    const rawThrown = bindings.__testAllVaultErrors()
    const thrown = rawThrown.filter(isBridgeErrorShape)
    assert.equal(
      thrown.length,
      rawThrown.length,
      'a __testAllVaultErrors() entry did not match the expected BridgeErrorShape',
    )

    // Exactly one thrown value per table code, matching
    // all_variants_for_parity_test()'s fixture list.
    const codes = thrown.map((t) => t.vaultErrorCode).sort()
    assert.deepEqual(codes, [...ALL_VAULT_ERROR_CODES].sort())

    const byCode = new Map(thrown.map((t) => [t.vaultErrorCode, t]))

    // `ctor: new (...args: never[]) => T` — see the doc comment on
    // `assertInstance` above for why `never[]`, not `unknown[]`, is the
    // correct typing for an instanceof-only constructor parameter.
    const expect = <T extends VaultError>(
      code: string,
      ctor: new (...args: never[]) => T,
      assertFields: (err: T) => void,
    ): void => {
      const raw = byCode.get(code)
      assert.ok(raw, `no bridge value for code ${code}`)
      const err = mapWasmError(raw)
      assertInstance(err, ctor, code)
      assertFields(err)
    }

    expect('secret-not-found', SecretNotFoundError, (err) => {
      assert.equal(err.message, 'secret not found')
    })
    expect('decryption', DecryptionError, (err) => {
      assert.equal(err.path, '/secrets/a.enc')
    })
    expect('token-expired', TokenExpiredError, (err) => {
      assert.equal(err.canRefresh, true)
    })
    expect('key-rotated', KeyRotatedError, (err) => {
      assert.equal(err.message, 'key rotated')
    })
    expect('key-revoked', KeyRevokedError, (err) => {
      assert.equal(err.message, 'key revoked')
    })
    expect('token-revoked', TokenRevokedError, (err) => {
      assert.equal(err.message, 'token revoked')
    })
    expect('usage-limit-exceeded', UsageLimitExceededError, (err) => {
      assert.equal(err.message, 'usage limit exceeded')
    })
    expect('rotation-in-progress', RotationInProgressError, (err) => {
      assert.equal(err.message, 'rotation in progress')
    })
    expect('backend-locked', BackendLockedError, (err) => {
      assert.equal(err.interactive, true)
    })
    expect('device-not-present', DeviceNotPresentError, (err) => {
      assert.equal(err.timeoutMs, 5000)
    })
    expect('authorization-denied', AuthorizationDeniedError, (err) => {
      assert.equal(err.message, 'authorization denied')
    })
    expect('backend-unavailable', BackendUnavailableError, (err) => {
      assert.equal(err.reason, 'all-failed')
      assert.deepEqual(err.attempted, ['keychain', 'file'])
    })
    expect('plugin-not-found', PluginNotFoundError, (err) => {
      assert.equal(err.plugin, 'vaultkeeper-1password')
      assert.equal(err.installUrl, 'https://example.test/install')
    })
    expect('identity-mismatch', IdentityMismatchError, (err) => {
      assert.equal(err.previousHash, 'aaaa')
      assert.equal(err.currentHash, 'bbbb')
    })
    expect('executable-trust-required', ExecutableTrustRequiredError, (err) => {
      assert.equal(err.reason, 'missing-choice')
      assert.ok(err.message.length > 0)
    })
    expect('invalid-algorithm', InvalidAlgorithmError, (err) => {
      assert.equal(err.algorithm, 'RS256')
      assert.deepEqual(err.allowed, ['EdDSA'])
    })
    expect('setup', SetupError, (err) => {
      assert.equal(err.dependency, 'openssl')
    })
    expect('filesystem', FilesystemError, (err) => {
      assert.equal(err.path, '/config/config.json')
      assert.equal(err.permission, 'read')
      assert.equal(err.code, 'EACCES')
    })
    expect('not-capable', NotCapableError, (err) => {
      assert.equal(err.backendType, 'keychain')
      assert.equal(err.capability, 'presencePerUse')
    })
    expect('presence-declined', PresenceDeclinedError, (err) => {
      assert.equal(err.backendType, 'yubikey')
    })
    expect('presence-timeout', PresenceTimeoutError, (err) => {
      assert.equal(err.backendType, 'yubikey')
      assert.equal(err.timeoutMs, 15000)
    })
    expect('invalid-key-material', InvalidKeyMaterialError, (err) => {
      assert.equal(err.message, 'invalid key material')
    })
    expect('signing-key-not-found', SigningKeyNotFoundError, (err) => {
      assert.equal(err.keyName, 'release-key')
    })
    expect('signing-key-already-exists', SigningKeyAlreadyExistsError, (err) => {
      assert.equal(err.keyName, 'release-key')
    })
    expect('signing-not-supported', SigningNotSupportedError, (err) => {
      assert.equal(err.backendType, 'keychain')
      assert.deepEqual(err.builtInSigningBackends, ['file'])
    })
    expect('exec', ExecError, (err) => {
      assert.equal(err.command, 'curl')
    })
    expect('fetch', FetchError, (err) => {
      assert.equal(err.url, 'https://example.test/{{secret}}')
    })
    expect('invalid-token', InvalidTokenError, (err) => {
      assert.equal(err.message, 'invalid token')
    })
    expect('accessor-consumed', AccessorConsumedError, (err) => {
      assert.equal(err.message, 'accessor consumed')
    })
    expect('config-validation', ConfigValidationError, (err) => {
      assert.equal(err.field, 'backends[0].path')
      assert.equal(err.configFilePath, '/config/config.json')
    })
    expect('unknown-backend-type', UnknownBackendTypeError, (err) => {
      assert.equal(err.field, 'backends[0].type')
      assert.equal(err.backendType, 'made-up')
      assert.deepEqual(err.knownTypes, ['file', 'keychain'])
      assert.equal(err.configFilePath, '/config/config.json')
    })
    expect('config-parse', ConfigParseError, (err) => {
      assert.equal(err.path, '/config/config.json')
      assert.equal(err.location, 'line 3, column 12')
    })

    // 'vault-error' (VaultError::Other) deliberately stays the base
    // VaultError class — there is no more specific subclass to reconstruct.
    const genericRaw = byCode.get('vault-error')
    assert.ok(genericRaw)
    const genericErr = mapWasmError(genericRaw)
    assert.equal(genericErr.constructor, VaultError)
    assert.equal(genericErr.message, 'generic vault error')
  })
})
