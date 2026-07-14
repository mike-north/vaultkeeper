/**
 * Integration test for `BackendConfig.path` plumbing (issue #60).
 *
 * Verifies that a custom `path` on a file backend config is honored end to end:
 * secrets land under the configured directory (created on demand) and NOT under
 * the default `$HOME/.vaultkeeper/file`, and that a second consumer built from
 * the same config reads and deletes them from that same directory.
 *
 * These tests use real temp directories and the real Node crypto file backend.
 * `$HOME` is redirected to an isolated temp dir so the real home is never
 * touched and "not under default location" can be asserted hermetically.
 *
 * @see https://github.com/mike-north/vaultkeeper/issues/60
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import * as fs from 'node:fs/promises'
import * as osModule from 'node:os'
import * as path from 'node:path'

// Redirect homedir before the backend modules compute any default path.
let overriddenHome = ''

vi.mock('node:os', async (importOriginal) => {
  const actual = await importOriginal<typeof osModule>()
  return {
    ...actual,
    homedir: () => (overriddenHome !== '' ? overriddenHome : actual.homedir()),
  }
})

import { VaultKeeper } from '../../../src/vault.js'
import { BackendRegistry } from '../../../src/backend/registry.js'
import { registerBuiltinBackends } from '../../../src/backend/register-builtins.js'
import type { VaultConfig, BackendConfig } from '../../../src/types.js'

let fakeHome = ''
let customDir = ''

/** Hex-encoded entry filename, matching FileBackend.getEntryPath. */
function entryFile(id: string): string {
  return `${Buffer.from(id, 'utf8').toString('hex')}.enc`
}

function configWithPath(storagePath: string): VaultConfig {
  const backend: BackendConfig = { type: 'file', enabled: true, path: storagePath }
  return {
    version: 1,
    backends: [backend],
    keyRotation: { gracePeriodDays: 7 },
    defaults: { ttlMinutes: 30, trustTier: 3 },
  }
}

beforeEach(async () => {
  // Ensure built-in backends are registered even though this test does not
  // import the package barrel (which normally triggers registration).
  registerBuiltinBackends()
  fakeHome = await fs.mkdtemp(path.join(osModule.tmpdir(), 'vk-home-'))
  customDir = await fs.mkdtemp(path.join(osModule.tmpdir(), 'vk-custom-'))
  overriddenHome = fakeHome
})

afterEach(async () => {
  overriddenHome = ''
  await fs.rm(fakeHome, { recursive: true, force: true })
  await fs.rm(customDir, { recursive: true, force: true })
  vi.restoreAllMocks()
})

describe('BackendConfig.path plumbing (file backend)', () => {
  it('stores the encrypted secret under the custom path and not the default home location', async () => {
    const config = configWithPath(customDir)
    const vault = await VaultKeeper.init({ skipDoctor: true, config, configDir: fakeHome })

    await vault.store('api-key', 'sk-live-abc123')

    // Encrypted entry exists under the configured directory.
    const customEntries = await fs.readdir(customDir)
    expect(customEntries).toContain(entryFile('api-key'))

    // Nothing was written to the default $HOME/.vaultkeeper/file location.
    const defaultDir = path.join(fakeHome, '.vaultkeeper', 'file')
    await expect(fs.readdir(defaultDir)).rejects.toMatchObject({ code: 'ENOENT' })
  })

  it('retrieves the secret through a backend built from the same config', async () => {
    const config = configWithPath(customDir)
    const vault = await VaultKeeper.init({ skipDoctor: true, config, configDir: fakeHome })
    await vault.store('api-key', 'sk-live-abc123')

    // #resolveBackend uses BackendRegistry.create(type, config); mirror that
    // path to read the value back from the custom directory.
    const backend = BackendRegistry.create('file', config.backends[0])
    expect(await backend.retrieve('api-key')).toBe('sk-live-abc123')
  })

  it('lets a second VaultKeeper instance with the same config delete from the custom path', async () => {
    const config = configWithPath(customDir)
    const vault1 = await VaultKeeper.init({ skipDoctor: true, config, configDir: fakeHome })
    await vault1.store('api-key', 'sk-live-abc123')
    expect(await fs.readdir(customDir)).toContain(entryFile('api-key'))

    const vault2 = await VaultKeeper.init({ skipDoctor: true, config, configDir: fakeHome })
    await vault2.delete('api-key')

    expect(await fs.readdir(customDir)).not.toContain(entryFile('api-key'))
  })

  it('uses the default home location when no path is configured', async () => {
    const config: VaultConfig = {
      version: 1,
      backends: [{ type: 'file', enabled: true }],
      keyRotation: { gracePeriodDays: 7 },
      defaults: { ttlMinutes: 30, trustTier: 3 },
    }
    const vault = await VaultKeeper.init({ skipDoctor: true, config, configDir: fakeHome })

    await vault.store('api-key', 'sk-live-abc123')

    const defaultDir = path.join(fakeHome, '.vaultkeeper', 'file')
    const entries = await fs.readdir(defaultDir)
    expect(entries).toContain(entryFile('api-key'))
  })
})
