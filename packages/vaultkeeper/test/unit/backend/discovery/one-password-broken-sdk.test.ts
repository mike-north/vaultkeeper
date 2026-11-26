/**
 * Verifies that a present-but-broken 1Password SDK (native binding failure,
 * init throw, incompatible Node) surfaces its REAL error during setup
 * discovery, rather than being misreported as "not installed" — which would
 * send the user to reinstall something already there.
 *
 * Regression for https://github.com/mike-north/vaultkeeper/issues/113.
 *
 * @see https://developer.1password.com/docs/sdks/
 */
import { describe, it, expect, vi } from 'vitest'

// Simulate a broken (not missing) SDK: importing it throws an error whose code
// is NOT a module-resolution failure. (Vitest wraps a mock-factory throw and
// attaches the original as `error.cause`, which isModuleNotFoundError inspects
// — matching how some real loaders wrap import failures.)
vi.mock('@1password/sdk', () => {
  const err = new Error('native binding failed to load: incompatible ABI')
  Object.assign(err, { code: 'ERR_DLOPEN_FAILED' })
  throw err
})

import { createOnePasswordSetup } from '../../../../src/backend/discovery/one-password.js'
import { PluginNotFoundError } from '../../../../src/errors.js'

describe('createOnePasswordSetup — SDK present but broken', () => {
  it('surfaces the real load error and does NOT report it as "not installed"', async () => {
    const gen = createOnePasswordSetup()
    await gen.next()
    const error = await gen.next('my-account').catch((err: unknown) => err)

    // The key invariant: a broken-but-present SDK is never misreported as the
    // missing-peer case, so the user isn't told to reinstall what they have.
    expect(error).not.toBeInstanceOf(PluginNotFoundError)
    expect(error).toBeInstanceOf(Error)
  })
})
