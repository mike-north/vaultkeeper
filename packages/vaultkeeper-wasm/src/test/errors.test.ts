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
import { mapWasmError, DecryptionError, VaultError } from '../errors.js';

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
