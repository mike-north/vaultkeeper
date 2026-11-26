/**
 * Proof for issue #98: the documented zero-config quick start must never
 * silently resolve to the real OS credential store.
 *
 * The shortest documented getting-started snippet is a bare
 * `await VaultKeeper.init()` with no config file present (README "TypeScript
 * quick start"). This test runs exactly that against an isolated, empty config
 * directory — standing in for a first-time user's untouched HOME — and asserts
 * the resolved active backend is the safe `file` backend, never `keychain`
 * (macOS) or `dpapi` (Windows).
 *
 * @see https://github.com/mike-north/vaultkeeper/issues/98
 */

import { describe, it, expect, afterEach } from 'vitest'
import * as fs from 'node:fs/promises'
import * as os from 'node:os'
import * as path from 'node:path'
import { VaultKeeper } from '../../src/vault.js'
import { defaultBackendType, platformNativeBackendType } from '../../src/config.js'

describe('zero-config default backend safety (issue #98)', () => {
  let configDir: string | undefined

  afterEach(async () => {
    if (configDir !== undefined) {
      await fs.rm(configDir, { recursive: true, force: true })
      configDir = undefined
    }
  })

  /** Create an empty, isolated config dir (a stand-in for an untouched HOME). */
  async function isolatedConfigDir(): Promise<string> {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'vk-issue98-'))
    configDir = dir
    return dir
  }

  it('resolves the exact documented VaultKeeper.init() quick start to the file backend, never the real keychain', async () => {
    // The documented snippet, verbatim, but pointed at an isolated empty dir so
    // no config file exists — the first-time-user path.
    const vault = await VaultKeeper.init({ configDir: await isolatedConfigDir() })

    // Acceptance criterion 4 / Proof: the resolved backend is the safe default,
    // not the OS-native credential store.
    expect(vault.activeBackendType).toBe('file')
    expect(vault.activeBackendType).toBe(defaultBackendType())
    expect(vault.activeBackendType).not.toBe('keychain')
    expect(vault.activeBackendType).not.toBe('dpapi')

    // Prove the resolved default is not the platform's native store wherever
    // that store differs from `file`: macOS (`keychain`), Windows (`dpapi`),
    // and Linux (`secret-tool`). The guard only skips on platforms with no
    // native-store integration (e.g. the BSDs), where the native type is
    // itself `file` and the inequality would be trivially false.
    if (platformNativeBackendType() !== 'file') {
      expect(vault.activeBackendType).not.toBe(platformNativeBackendType())
    }
  })

  it('does not write any config file as a side effect of the zero-config default', async () => {
    const dir = await isolatedConfigDir()
    await VaultKeeper.init({ configDir: dir })

    // The safe default is resolved in-memory; storing a secret must not require
    // — and init must not silently create — a config.json the user never asked
    // for. (Key material may be persisted; a config file must not be.)
    await expect(fs.access(path.join(dir, 'config.json'))).rejects.toThrow()
  })
})
