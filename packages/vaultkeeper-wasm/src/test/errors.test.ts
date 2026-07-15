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

import { describe, it } from 'node:test';
import * as assert from 'node:assert/strict';
import { mapWasmError, DecryptionError, FilesystemError, VaultError } from '../errors.js';

describe('mapWasmError — decryption code', () => {
  it('carries the path through when the boundary supplies one', () => {
    const err = mapWasmError({
      vaultErrorCode: 'decryption',
      message: 'auth tag verification failed',
      path: '/config/file/deadbeef.enc',
    });
    assert.ok(err instanceof DecryptionError && err instanceof VaultError);
    assert.equal(err.path, '/config/file/deadbeef.enc');
  });

  // Regression test for PR #135 review feedback: a missing `path` on the
  // thrown shape must surface as `undefined`, not a fabricated empty
  // string — an empty string would be indistinguishable from a (never
  // actually possible) genuine empty path and would hide a bridge bug.
  it('leaves path undefined, not an empty string, when the boundary omits it', () => {
    const err = mapWasmError({
      vaultErrorCode: 'decryption',
      message: 'auth tag verification failed',
    });
    assert.ok(err instanceof DecryptionError && err instanceof VaultError);
    assert.equal(err.path, undefined);
    assert.notEqual(err.path, '', 'must not fabricate an empty-string path');
  });
});

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
    });
    assert.ok(err instanceof FilesystemError && err instanceof VaultError);
    assert.equal(err.path, '/config/file/deadbeef.enc');
    assert.equal(err.permission, 'read');
    assert.equal(err.code, 'EACCES');
  });

  it('leaves code undefined, not fabricated, when the host bridge could not determine one', () => {
    const err = mapWasmError({
      vaultErrorCode: 'filesystem',
      message: 'Failed to delete /config/file/deadbeef.enc: unknown failure',
      path: '/config/file/deadbeef.enc',
      permission: 'write',
    });
    assert.ok(err instanceof FilesystemError && err instanceof VaultError);
    assert.equal(err.code, undefined);
  });

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
    });
    assert.ok(err instanceof FilesystemError && err instanceof VaultError);
    assert.equal(err.code, 'EACCES');
    assert.equal(err.path, undefined);
    assert.notEqual(err.path, '', 'must not fabricate an empty-string path');
    assert.equal(err.permission, undefined);
    assert.notEqual(err.permission, '', 'must not fabricate an empty-string permission');
  });
});
