/**
 * Unit tests for the backend capability contract (issue #122).
 *
 * Covers the extension interface, the safe-default helper, the type guard, and
 * each built-in backend's per-configured-instance truth for `presencePerUse`.
 *
 * @see https://github.com/mike-north/vaultkeeper/issues/122
 */

import { describe, it, expect } from 'vitest'
import { getBackendCapabilities, isPresenceCapableBackend } from '../../../src/backend/types.js'
import type {
  SecretBackend,
  PresenceCapableBackend,
  BackendCapabilities,
} from '../../../src/backend/types.js'
import { FileBackend } from '../../../src/backend/file-backend.js'
import { YubikeyBackend } from '../../../src/backend/yubikey-backend.js'
import { OnePasswordBackend } from '../../../src/backend/one-password-backend.js'

/** A minimal backend that does NOT implement the capability interface. */
const plainBackend: SecretBackend = {
  type: 'plain',
  displayName: 'Plain',
  isAvailable: () => Promise.resolve(true),
  store: () => Promise.resolve(),
  retrieve: () => Promise.resolve(''),
  delete: () => Promise.resolve(),
  exists: () => Promise.resolve(false),
}

describe('backend capability contract (AC1)', () => {
  it('a backend without the interface reports presencePerUse: false via the helper', async () => {
    // AC1: unknown backends never silently claim presence.
    await expect(getBackendCapabilities(plainBackend)).resolves.toEqual({
      presencePerUse: false,
    })
  })

  it('isPresenceCapableBackend is false for a backend without getCapabilities', () => {
    expect(isPresenceCapableBackend(plainBackend)).toBe(false)
  })

  it('isPresenceCapableBackend is true for a backend implementing getCapabilities', () => {
    const capable: PresenceCapableBackend = {
      ...plainBackend,
      getCapabilities: (): Promise<BackendCapabilities> =>
        Promise.resolve({ presencePerUse: true }),
    }
    expect(isPresenceCapableBackend(capable)).toBe(true)
  })

  it('the helper delegates to getCapabilities when the interface is present', async () => {
    const capable: PresenceCapableBackend = {
      ...plainBackend,
      getCapabilities: (): Promise<BackendCapabilities> =>
        Promise.resolve({ presencePerUse: true }),
    }
    await expect(getBackendCapabilities(capable)).resolves.toEqual({ presencePerUse: true })
  })
})

describe('per-backend truth basis (AC2)', () => {
  it('file backend reports presencePerUse: false', async () => {
    // Encryption-only, no per-use human action.
    await expect(getBackendCapabilities(new FileBackend('/tmp/vk-caps-file'))).resolves.toEqual({
      presencePerUse: false,
    })
  })

  it('YubiKey reports true only when the configured slot enforces touch per operation', async () => {
    // Derived from configuration, never hardcoded by type: two instances of the
    // same type differ purely by their configured touch policy.
    const withTouch = new YubikeyBackend('/tmp/vk-caps-yk', true)
    const withoutTouch = new YubikeyBackend('/tmp/vk-caps-yk', false)
    await expect(withTouch.getCapabilities()).resolves.toEqual({
      presencePerUse: true,
      presenceEnforcedOperations: ['read', 'store'],
    })
    await expect(withoutTouch.getCapabilities()).resolves.toEqual({ presencePerUse: false })
  })

  it('YubiKey excludes delete from presenceEnforcedOperations (regression, issue #326)', async () => {
    // delete() never performs challenge-response — it only probes device
    // presence (requireDevice) and unlinks the entry — so a touch-configured
    // slot must not claim `delete` is presence-enforced. Before the fix,
    // getCapabilities omitted `presenceEnforcedOperations` entirely, which
    // the shared capability contract treats as "every keyed operation is
    // covered" — silently misrepresenting `delete` as touch-gated.
    const withTouch = new YubikeyBackend('/tmp/vk-caps-yk', true)
    const caps = await withTouch.getCapabilities()
    expect(caps.presencePerUse).toBe(true)
    expect(caps.presenceEnforcedOperations).toEqual(['read', 'store'])
    expect(caps.presenceEnforcedOperations).not.toContain('delete')
  })

  it('YubiKey defaults to false when no touch policy is configured', async () => {
    await expect(new YubikeyBackend('/tmp/vk-caps-yk').getCapabilities()).resolves.toEqual({
      presencePerUse: false,
    })
  })

  it('1Password reports true only in per-access mode, covering read, store, and delete', async () => {
    // per-access forces a fresh per-operation biometric approval for every
    // keyed operation — reads route through the per-access worker (shipped in
    // #210), and store/delete now do too (#211 closed the earlier gap where
    // writes rode the cached session client). Session mode rides one cached
    // unlock for everything, so it reports false.
    const perAccess = new OnePasswordBackend({ vault: 'v', accessMode: 'per-access' })
    const session = new OnePasswordBackend({ vault: 'v', accessMode: 'session' })
    await expect(perAccess.getCapabilities()).resolves.toEqual({
      presencePerUse: true,
      presenceEnforcedOperations: ['read', 'store', 'delete'],
    })
    await expect(session.getCapabilities()).resolves.toEqual({ presencePerUse: false })
  })

  it('1Password defaults to session mode (presencePerUse: false)', async () => {
    await expect(new OnePasswordBackend({ vault: 'v' }).getCapabilities()).resolves.toEqual({
      presencePerUse: false,
    })
  })
})
