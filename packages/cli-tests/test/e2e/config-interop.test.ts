/**
 * Cross-package interop UAT for the config wire format (issue #200).
 *
 * A config directory produced by the documented `vaultkeeper config init` flow
 * must be readable by every consumer that reads it: the TS library
 * (`vaultkeeper`) and the WASM SDK (`@vaultkeeper/wasm`, backed by Rust core).
 * The regression this guards: `config init` writes `"trustTier": 3` as a bare
 * JSON number (matching the README example), but the Rust-core reader used to
 * require a string-encoded number, so `createVaultKeeper()` threw
 * `Failed to parse config` on a CLI-produced config dir.
 *
 * This test round-trips a *real* `config init` output — it does not hand-write
 * the config — so it fails if the CLI writer and any reader ever diverge again.
 */
import { describe, it, expect, afterEach } from 'vitest'
import * as fs from 'node:fs/promises'
import * as path from 'node:path'
import { createCliTestEnv } from '@vaultkeeper/cli-test-helpers'
import type { CliTestEnv } from '@vaultkeeper/cli-test-helpers'
import { loadConfig } from 'vaultkeeper'
import { createVaultKeeper } from '@vaultkeeper/wasm'

describe('config init cross-package interop (issue #200)', () => {
  let env: CliTestEnv | undefined

  afterEach(async () => {
    if (env !== undefined) {
      await env.cleanup()
      env = undefined
    }
  })

  /** Create an env and remove the config.json that createCliTestEnv seeds. */
  async function freshEnv(): Promise<CliTestEnv> {
    const created = await createCliTestEnv()
    await fs.rm(path.join(created.configDir, 'config.json'))
    return created
  }

  it('writes trustTier as a bare JSON number, the canonical wire form', async () => {
    env = await freshEnv()
    const result = await env.run(['config', 'init', '--backend', 'file'])
    expect(result.exitCode).toBe(0)

    // Assert against the raw text: the field must be a number token (`3`),
    // never a quoted string (`"3"`). This is the canonical form the README
    // and TS library also use.
    const raw = await fs.readFile(path.join(env.configDir, 'config.json'), 'utf8')
    expect(raw).toMatch(/"trustTier":\s*3\b/)
    expect(raw).not.toMatch(/"trustTier":\s*"3"/)

    const parsed: unknown = JSON.parse(raw)
    expect(parsed).toMatchObject({ defaults: { trustTier: 3 } })
  })

  it('the TS library loadConfig() reads a config init directory', async () => {
    env = await freshEnv()
    const result = await env.run(['config', 'init', '--backend', 'file'])
    expect(result.exitCode).toBe(0)

    const config = await loadConfig(env.configDir)
    expect(config.version).toBe(1)
    expect(config.defaults.trustTier).toBe(3)
  })

  it('the WASM SDK createVaultKeeper() reads a config init directory', async () => {
    env = await freshEnv()
    const result = await env.run(['config', 'init', '--backend', 'file'])
    expect(result.exitCode).toBe(0)

    // Before the fix this threw `VaultError: Failed to parse config` because the
    // Rust-core reader rejected the numeric trustTier.
    const vault = await createVaultKeeper({ skipDoctor: true }, env.configDir)
    try {
      expect(vault.config().version).toBe(1)
    } finally {
      vault.dispose()
    }
  })
})
