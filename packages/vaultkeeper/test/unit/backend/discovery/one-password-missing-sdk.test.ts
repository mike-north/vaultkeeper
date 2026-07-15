/**
 * Verifies the 1Password setup discovery degrades with a typed
 * PluginNotFoundError (naming the missing @1password/sdk peer) when the
 * optional SDK is not installed, rather than a raw module-not-found error.
 *
 * Regression for https://github.com/mike-north/vaultkeeper/issues/113.
 *
 * @see https://developer.1password.com/docs/sdks/
 */
import { describe, it, expect, vi } from 'vitest'

// Simulate the optional peer being absent: importing '@1password/sdk' rejects,
// exactly as it would when the package is not installed.
vi.mock('@1password/sdk', () => {
  throw new Error("Cannot find package '@1password/sdk'")
})

import { createOnePasswordSetup } from '../../../../src/backend/discovery/one-password.js'
import { PluginNotFoundError } from '../../../../src/errors.js'

describe('createOnePasswordSetup — SDK not installed', () => {
  it('throws a typed PluginNotFoundError naming @1password/sdk', async () => {
    const gen = createOnePasswordSetup()
    // First yield asks for the account name; the SDK load happens after we
    // supply it, when the setup tries to create a client.
    await gen.next()
    const error = await gen.next('my-account').catch((err: unknown) => err)

    expect(error).toBeInstanceOf(PluginNotFoundError)
    expect(error).toMatchObject({ plugin: '@1password/sdk' })
  })
})
