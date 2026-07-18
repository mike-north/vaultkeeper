/**
 * Unit tests for the @vaultkeeper/wasm error-mapping bridge (mapWasmError).
 *
 * These exercise the fallback behavior for malformed/incomplete boundary
 * shapes directly — scenarios the real WASM core never actually produces
 * (it always supplies a `path` for `decryption`), but which the bridge must
 * still handle without fabricating data.
 *
 * Uses node:test (not vitest) since this package compiles with plain tsc.
 */

/* eslint-disable @typescript-eslint/no-floating-promises -- node:test it() returns Promise but is not meant to be awaited inside describe() */
/* eslint-disable n/no-unsupported-features/node-builtins -- test.describe is stable in our CI Node version */

import { describe, it } from 'node:test'
import * as assert from 'node:assert/strict'
import {
  mapWasmError,
  DecryptionError,
  FilesystemError,
  IdentityMismatchError,
  BackendUnavailableError,
  DeviceNotPresentError,
  ConfigParseError,
  VaultError,
} from '../errors.js'

// Regression test for PR #251 review feedback: optionalStringArray() used
// Array#every, which vacuously accepts sparse-array holes (every() skips
// them rather than visiting them as undefined). A thrown boundary value with
// a hole-filled array would have been accepted as string[] even though a
// hole reads back as undefined, not a string — violating the field's
// documented string[] contract.
describe('mapWasmError — backend-unavailable code (sparse-array hole rejection)', () => {
  it('rejects a sparse-array `attempted` value and falls back to an empty array, not the hole-filled array', () => {
    const sparse = new Array<string>(2)
    sparse[1] = 'file' // index 0 left as a hole
    const err = mapWasmError({
      vaultErrorCode: 'backend-unavailable',
      message: 'no backend available',
      reason: 'all-failed',
      attempted: sparse,
    })
    assert.ok(err instanceof BackendUnavailableError && err instanceof VaultError)
    assert.deepEqual(err.attempted, [])
    assert.notEqual(err.attempted, sparse, 'must not pass the hole-filled array through as-is')
  })

  it('still accepts a genuine string[] `attempted` value', () => {
    const err = mapWasmError({
      vaultErrorCode: 'backend-unavailable',
      message: 'no backend available',
      reason: 'all-failed',
      attempted: ['keychain', 'file'],
    })
    assert.ok(err instanceof BackendUnavailableError)
    assert.deepEqual(err.attempted, ['keychain', 'file'])
  })
})

// Regression test for PR #251 review feedback: optionalNumber() only checked
// `typeof value === 'number'`, so NaN/Infinity/non-integer values passed
// through unchanged — they could leak into a typed field (e.g. `timeoutMs`)
// or produce a nonsensical formatted string (e.g. `toConfigParseLocation`'s
// `'line NaN, column 12'`).
describe('mapWasmError — non-finite/non-integer number rejection', () => {
  it('falls back to the default timeoutMs (0) for a NaN boundary value, not NaN itself', () => {
    const err = mapWasmError({
      vaultErrorCode: 'device-not-present',
      message: 'device not present',
      timeoutMs: Number.NaN,
    })
    assert.ok(err instanceof DeviceNotPresentError)
    assert.equal(err.timeoutMs, 0)
    assert.notEqual(Number.isNaN(err.timeoutMs), true, 'must not leak NaN into timeoutMs')
  })

  it('falls back to the default timeoutMs (0) for an Infinity boundary value', () => {
    const err = mapWasmError({
      vaultErrorCode: 'device-not-present',
      message: 'device not present',
      timeoutMs: Number.POSITIVE_INFINITY,
    })
    assert.ok(err instanceof DeviceNotPresentError)
    assert.equal(err.timeoutMs, 0)
  })

  it('leaves `location` undefined, not "line NaN, column 12", when `line` is NaN', () => {
    const err = mapWasmError({
      vaultErrorCode: 'config-parse',
      message: 'config parse failed',
      path: '/config.json',
      line: Number.NaN,
      column: 12,
    })
    assert.ok(err instanceof ConfigParseError)
    assert.equal(err.location, undefined)
  })

  it('leaves `location` undefined when `line` is 0 — the contract is 1-based', () => {
    const err = mapWasmError({
      vaultErrorCode: 'config-parse',
      message: 'config parse failed',
      path: '/config.json',
      line: 0,
      column: 12,
    })
    assert.ok(err instanceof ConfigParseError)
    assert.equal(err.location, undefined)
  })

  it('falls back to the default timeoutMs (0) for a negative boundary value', () => {
    const err = mapWasmError({
      vaultErrorCode: 'device-not-present',
      message: 'device not present',
      timeoutMs: -1,
    })
    assert.ok(err instanceof DeviceNotPresentError)
    assert.equal(err.timeoutMs, 0)
  })

  it('still accepts a genuine safe-integer timeoutMs', () => {
    const err = mapWasmError({
      vaultErrorCode: 'device-not-present',
      message: 'device not present',
      timeoutMs: 5000,
    })
    assert.ok(err instanceof DeviceNotPresentError)
    assert.equal(err.timeoutMs, 5000)
  })
})

describe('mapWasmError — decryption code', () => {
  it('carries the path through when the boundary supplies one', () => {
    const err = mapWasmError({
      vaultErrorCode: 'decryption',
      message: 'auth tag verification failed',
      path: '/config/file/deadbeef.enc',
    })
    assert.ok(err instanceof DecryptionError && err instanceof VaultError)
    assert.equal(err.path, '/config/file/deadbeef.enc')
  })

  // Regression test for PR #135 review feedback: a missing `path` on the
  // thrown shape must surface as `undefined`, not a fabricated empty
  // string — an empty string would be indistinguishable from a (never
  // actually possible) genuine empty path and would hide a bridge bug.
  it('leaves path undefined, not an empty string, when the boundary omits it', () => {
    const err = mapWasmError({
      vaultErrorCode: 'decryption',
      message: 'auth tag verification failed',
    })
    assert.ok(err instanceof DecryptionError && err instanceof VaultError)
    assert.equal(err.path, undefined)
    assert.notEqual(err.path, '', 'must not fabricate an empty-string path')
  })
})

// Regression tests for issue #138: the WASM host bridge previously erased
// the errno on every readFile/deleteFile rejection, so `FilesystemError`
// never made it across the boundary. These pin the `mapWasmError` side of
// the fix directly; sdk.test.ts covers the same contract end-to-end through
// real chmod-based fixtures.
describe('mapWasmError — filesystem code (issue #138)', () => {
  it('carries path, permission, and code through when the boundary supplies all three', () => {
    const err = mapWasmError({
      vaultErrorCode: 'filesystem',
      message: 'Failed to read /config/file/deadbeef.enc: EACCES',
      path: '/config/file/deadbeef.enc',
      permission: 'read',
      code: 'EACCES',
    })
    assert.ok(err instanceof FilesystemError && err instanceof VaultError)
    assert.equal(err.path, '/config/file/deadbeef.enc')
    assert.equal(err.permission, 'read')
    assert.equal(err.code, 'EACCES')
  })

  it('leaves code undefined, not fabricated, when the host bridge could not determine one', () => {
    const err = mapWasmError({
      vaultErrorCode: 'filesystem',
      message: 'Failed to delete /config/file/deadbeef.enc: unknown failure',
      path: '/config/file/deadbeef.enc',
      permission: 'write',
    })
    assert.ok(err instanceof FilesystemError && err instanceof VaultError)
    assert.equal(err.code, undefined)
  })

  // Regression test for a PR #154 review follow-up: the real WASM core
  // always supplies `path`/`permission` for a `filesystem`-coded thrown
  // value, but a malformed/adversarial boundary shape (never produced by
  // the real core, but not impossible for `mapWasmError` to receive) could
  // omit them. This still constructs a `FilesystemError` — a
  // filesystem-coded error with undefined path/permission remains more
  // truthful than downgrading to the generic `VaultError` base class, which
  // would hide `code` and the fact that this was a filesystem failure at
  // all — and leaves the missing fields honestly `undefined`, not
  // fabricated as empty strings (mirroring `decryption`'s `path` handling).
  it('constructs a FilesystemError (not a generic VaultError) with path/permission left undefined, not fabricated, when the boundary omits them', () => {
    const err = mapWasmError({
      vaultErrorCode: 'filesystem',
      message: 'Failed to read: EACCES',
      code: 'EACCES',
    })
    assert.ok(err instanceof FilesystemError && err instanceof VaultError)
    assert.equal(err.code, 'EACCES')
    assert.equal(err.path, undefined)
    assert.notEqual(err.path, '', 'must not fabricate an empty-string path')
    assert.equal(err.permission, undefined)
    assert.notEqual(err.permission, '', 'must not fabricate an empty-string permission')
  })
})

// Issue #166: setup()'s executable-trust verification surfaces a TOFU hash
// conflict as an `identity-mismatch`-coded value. These pin the `mapWasmError`
// side of that contract — the reconstructed typed error must carry the hashes.
describe('mapWasmError — identity-mismatch code (issue #166)', () => {
  it('reconstructs a typed IdentityMismatchError carrying previous and current hashes', () => {
    const err = mapWasmError({
      vaultErrorCode: 'identity-mismatch',
      message: 'Executable hash changed — re-approval required',
      previousHash: 'aaaa',
      currentHash: 'bbbb',
    })
    assert.ok(err instanceof IdentityMismatchError && err instanceof VaultError)
    assert.equal(err.previousHash, 'aaaa')
    assert.equal(err.currentHash, 'bbbb')
  })

  it('leaves the hashes undefined, not fabricated, when the boundary omits them', () => {
    const err = mapWasmError({
      vaultErrorCode: 'identity-mismatch',
      message: 'Executable hash changed — re-approval required',
    })
    assert.ok(err instanceof IdentityMismatchError)
    assert.equal(err.previousHash, undefined)
    assert.notEqual(err.previousHash, '', 'must not fabricate an empty-string hash')
    assert.equal(err.currentHash, undefined)
    assert.notEqual(err.currentHash, '', 'must not fabricate an empty-string hash')
  })

  it('drops non-string hashes to undefined, honoring the string | undefined contract', () => {
    // A malformed boundary shape (null / number) must not land as a non-string
    // field on the typed error.
    const err = mapWasmError({
      vaultErrorCode: 'identity-mismatch',
      message: 'Executable hash changed — re-approval required',
      previousHash: null,
      currentHash: 123,
    })
    assert.ok(err instanceof IdentityMismatchError)
    assert.equal(err.previousHash, undefined)
    assert.equal(err.currentHash, undefined)
  })
})
