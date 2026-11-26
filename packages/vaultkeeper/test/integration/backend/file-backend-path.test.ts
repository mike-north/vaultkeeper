/**
 * Integration tests for file-backend path isolation and legacy fallback.
 *
 * Verifies that a custom `path` on a file backend config is honored end to end:
 * secrets land under the configured directory and a second consumer with the
 * same config reads and deletes them there. Default-path deletes also cover
 * the legacy `$HOME/.vaultkeeper/file` lookup source.
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

// Use the real filesystem and let tests observe the boundary between unlinks.
vi.mock('node:fs/promises', async (importOriginal) => {
  const actual = await importOriginal<typeof fs>()
  return { ...actual, unlink: vi.fn(actual.unlink) }
})

import { FileBackend } from '../../../src/backend/file-backend.js'
import { FilesystemError, SecretNotFoundError } from '../../../src/errors.js'
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

function fileConfig(storagePath?: string): VaultConfig {
  const backend: BackendConfig =
    storagePath === undefined
      ? { type: 'file', enabled: true }
      : { type: 'file', enabled: true, path: storagePath }
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
    const config = fileConfig(customDir)
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
    const config = fileConfig(customDir)
    const vault = await VaultKeeper.init({ skipDoctor: true, config, configDir: fakeHome })
    await vault.store('api-key', 'sk-live-abc123')

    // #resolveBackend uses BackendRegistry.create(type, config); mirror that
    // path to read the value back from the custom directory.
    const backend = BackendRegistry.create('file', config.backends[0])
    expect(await backend.retrieve('api-key')).toBe('sk-live-abc123')
  })

  it('lets a second VaultKeeper instance with the same config delete from the custom path', async () => {
    const config = fileConfig(customDir)
    const legacyBackend = new FileBackend(path.join(fakeHome, '.vaultkeeper', 'file'))
    await legacyBackend.store('api-key', 'legacy-kept')
    const vault1 = await VaultKeeper.init({ skipDoctor: true, config, configDir: fakeHome })
    await vault1.store('api-key', 'sk-live-abc123')
    expect(await fs.readdir(customDir)).toContain(entryFile('api-key'))

    const vault2 = await VaultKeeper.init({ skipDoctor: true, config, configDir: fakeHome })
    await vault2.delete('api-key')

    expect(await fs.readdir(customDir)).not.toContain(entryFile('api-key'))
    await expect(legacyBackend.retrieve('api-key')).resolves.toBe('legacy-kept')
  })

  it('uses the resolved config dir when no path is configured (issue #99)', async () => {
    const config: VaultConfig = {
      version: 1,
      backends: [{ type: 'file', enabled: true }],
      keyRotation: { gracePeriodDays: 7 },
      defaults: { ttlMinutes: 30, trustTier: 3 },
    }
    const vault = await VaultKeeper.init({ skipDoctor: true, config, configDir: fakeHome })

    await vault.store('api-key', 'sk-live-abc123')

    // Default storage now lives under the resolved config dir (fakeHome/file),
    // not the legacy $HOME/.vaultkeeper/file location.
    const configDirDefault = path.join(fakeHome, 'file')
    const entries = await fs.readdir(configDirDefault)
    expect(entries).toContain(entryFile('api-key'))

    const legacyDir = path.join(fakeHome, '.vaultkeeper', 'file')
    await expect(fs.readdir(legacyDir)).rejects.toMatchObject({ code: 'ENOENT' })
  })

  it('reads a secret from the legacy $HOME/.vaultkeeper/file location when absent from the new default (issue #99 back-compat)', async () => {
    // Simulate a secret written under the pre-#99 default before this fix
    // existed, using a fresh FileBackend pointed directly at the legacy dir.
    const legacyDir = path.join(fakeHome, '.vaultkeeper', 'file')
    const legacyBackend = BackendRegistry.create('file', {
      type: 'file',
      enabled: true,
      path: legacyDir,
    })
    await legacyBackend.store('legacy-key', 'legacy-secret-value')

    const config: VaultConfig = {
      version: 1,
      backends: [{ type: 'file', enabled: true }],
      keyRotation: { gracePeriodDays: 7 },
      defaults: { ttlMinutes: 30, trustTier: 3 },
    }
    const vault = await VaultKeeper.init({ skipDoctor: true, config, configDir: fakeHome })

    const jwe = await vault.setup('legacy-key', { skipTrust: true })
    const { token } = await vault.authorize(jwe)
    let secret: string | undefined
    vault.getSecret(token).read((buf) => {
      secret = buf.toString('utf8')
    })
    expect(secret).toBe('legacy-secret-value')

    // New default location was never written to by the legacy-only read.
    const configDirDefault = path.join(fakeHome, 'file')
    await expect(fs.readdir(configDirDefault)).rejects.toMatchObject({ code: 'ENOENT' })

    await vault.delete('legacy-key')
    await expect(legacyBackend.retrieve('legacy-key')).rejects.toBeInstanceOf(SecretNotFoundError)
    await expect(vault.delete('legacy-key')).rejects.toBeInstanceOf(SecretNotFoundError)
  })

  it('deletes current and legacy copies without affecting unrelated or custom-path records', async () => {
    const legacyBackend = new FileBackend(path.join(fakeHome, '.vaultkeeper', 'file'))
    const customBackend = new FileBackend(customDir)
    const vault = await VaultKeeper.init({
      skipDoctor: true,
      config: fileConfig(),
      configDir: fakeHome,
    })

    await vault.store('rotated-key', 'current-value')
    await legacyBackend.store('rotated-key', 'retired-value')
    await vault.store('current-unrelated', 'current-kept')
    await legacyBackend.store('legacy-unrelated', 'legacy-kept')
    await customBackend.store('rotated-key', 'custom-kept')
    await expect(new FileBackend(undefined, fakeHome).retrieve('rotated-key')).resolves.toBe(
      'current-value',
    )

    await vault.delete('rotated-key')

    const reopened = new FileBackend(undefined, fakeHome)
    await expect(reopened.retrieve('rotated-key')).rejects.toBeInstanceOf(SecretNotFoundError)
    await expect(reopened.exists('rotated-key')).resolves.toBe(false)
    expect(new Set(await reopened.list())).toEqual(
      new Set(['current-unrelated', 'legacy-unrelated']),
    )
    await expect(reopened.retrieve('current-unrelated')).resolves.toBe('current-kept')
    await expect(reopened.retrieve('legacy-unrelated')).resolves.toBe('legacy-kept')
    await expect(new FileBackend(customDir).retrieve('rotated-key')).resolves.toBe('custom-kept')
  })

  it('keeps the current value visible to a reader between the two unlinks', async () => {
    const backend = new FileBackend(undefined, fakeHome)
    const legacyBackend = new FileBackend(path.join(fakeHome, '.vaultkeeper', 'file'))
    await backend.store('rotated-key', 'current-value')
    await legacyBackend.store('rotated-key', 'retired-value')

    const actualFs = await vi.importActual<typeof fs>('node:fs/promises')
    let observedDuringDelete: string | undefined
    vi.mocked(fs.unlink).mockImplementationOnce(async (entryPath) => {
      await actualFs.unlink(entryPath)
      observedDuringDelete = await new FileBackend(undefined, fakeHome).retrieve('rotated-key')
    })

    await backend.delete('rotated-key')

    expect(observedDuringDelete).toBe('current-value')
    await expect(backend.retrieve('rotated-key')).rejects.toBeInstanceOf(SecretNotFoundError)
  })

  it('preserves the current value when the legacy unlink fails and permits a retry', async () => {
    const backend = new FileBackend(undefined, fakeHome)
    const legacyDir = path.join(fakeHome, '.vaultkeeper', 'file')
    const legacyEntry = path.join(legacyDir, entryFile('rotated-key'))
    await backend.store('rotated-key', 'current-value')
    await fs.mkdir(legacyEntry, { recursive: true })

    await expect(backend.delete('rotated-key')).rejects.toMatchObject({
      name: FilesystemError.name,
      path: legacyEntry,
      permission: 'delete',
    })
    const reopened = new FileBackend(undefined, fakeHome)
    await expect(reopened.retrieve('rotated-key')).resolves.toBe('current-value')

    await fs.rmdir(legacyEntry)
    await new FileBackend(legacyDir).store('rotated-key', 'retired-value')
    await reopened.delete('rotated-key')
    await expect(reopened.retrieve('rotated-key')).rejects.toBeInstanceOf(SecretNotFoundError)
  })

  it('unlinks the entry once when the config directory already points at the legacy store', async () => {
    const configDir = path.join(fakeHome, '.vaultkeeper')
    const backend = new FileBackend(undefined, configDir)
    await backend.store('key', 'value')
    const unlink = vi.mocked(fs.unlink)
    unlink.mockClear()

    await backend.delete('key')

    expect(unlink).toHaveBeenCalledExactlyOnceWith(path.join(configDir, 'file', entryFile('key')))
    await expect(backend.retrieve('key')).rejects.toBeInstanceOf(SecretNotFoundError)
  })

  it('preserves a concurrent replacement when the storage directories are aliases', async () => {
    const backend = new FileBackend(undefined, fakeHome)
    const legacyDir = path.join(fakeHome, '.vaultkeeper', 'file')
    await backend.store('rotated-key', 'current-value')
    await fs.mkdir(path.dirname(legacyDir))
    await fs.symlink(path.join(fakeHome, 'file'), legacyDir, 'junction')

    const actualFs = await vi.importActual<typeof fs>('node:fs/promises')
    const writer = new FileBackend(undefined, fakeHome)
    const unlink = vi.mocked(fs.unlink)
    unlink.mockClear()
    unlink.mockImplementationOnce(async (entryPath) => {
      await actualFs.unlink(entryPath)
      await writer.store('rotated-key', 'replacement-value')
    })

    await backend.delete('rotated-key')

    expect(unlink).toHaveBeenCalledTimes(1)
    await expect(writer.retrieve('rotated-key')).resolves.toBe('replacement-value')
  })

  // Acceptance criterion 4: no-path store lands under the resolved config
  // dir, and a second VaultKeeper against the same config dir reads it back.
  it('lets a second VaultKeeper against the same config dir read back a no-path store (criterion 4)', async () => {
    const config: VaultConfig = {
      version: 1,
      backends: [{ type: 'file', enabled: true }],
      keyRotation: { gracePeriodDays: 7 },
      defaults: { ttlMinutes: 30, trustTier: 3 },
      developmentMode: { executables: ['dev'] },
    }
    const configDir = await fs.mkdtemp(path.join(osModule.tmpdir(), 'vk-cfgdir-'))
    try {
      const vault1 = await VaultKeeper.init({ skipDoctor: true, config, configDir })
      await vault1.store('api-key', 'sk-live-abc123')

      const storageDir = path.join(configDir, 'file')
      expect(await fs.readdir(storageDir)).toContain(entryFile('api-key'))

      const vault2 = await VaultKeeper.init({ skipDoctor: true, config, configDir })
      const jwe = await vault2.setup('api-key', { skipTrust: true })
      const { token } = await vault2.authorize(jwe)
      let secret: string | undefined
      vault2.getSecret(token).read((buf) => {
        secret = buf.toString('utf8')
      })
      expect(secret).toBe('sk-live-abc123')
    } finally {
      await fs.rm(configDir, { recursive: true, force: true })
    }
  })
})
