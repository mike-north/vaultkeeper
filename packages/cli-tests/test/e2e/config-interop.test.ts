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
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto'
import * as fs from 'node:fs/promises'
import * as path from 'node:path'
import { createCliTestEnv } from '@vaultkeeper/cli-test-helpers'
import type { CliTestEnv } from '@vaultkeeper/cli-test-helpers'
import { VaultKeeper, loadConfig } from 'vaultkeeper'
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

describe('shared key state across the TypeScript and WASM SDKs (issue #382)', () => {
  let env: CliTestEnv | undefined

  afterEach(async () => {
    await env?.cleanup()
  })

  it('preserves newer revocation metadata during rotation by an already-open SDK', async () => {
    env = await createCliTestEnv()
    const configDir = env.configDir
    const stale = await VaultKeeper.init({ configDir, skipDoctor: true })
    const wasm = await createVaultKeeper({ skipDoctor: true }, configDir)
    const statePath = path.join(configDir, 'keys.enc')
    const wrap = await fs.readFile(path.join(configDir, '.keys.wrap'))
    const metadata =
      '"revStateGen":18446744073709551615,"jti":[{"jti":"brace } and comma ,","exp":18446744073709551615}],"keyGenerations":{"signer":18446744073709551615}'
    async function readState(): Promise<string> {
      const [iv, tag, ciphertext] = (await fs.readFile(statePath, 'utf8')).split(':')
      if (iv === undefined || tag === undefined || ciphertext === undefined) return ''
      const decipher = createDecipheriv('aes-256-gcm', wrap, Buffer.from(iv, 'base64'))
      decipher.setAuthTag(Buffer.from(tag, 'base64'))
      return decipher.update(ciphertext, 'base64', 'utf8') + decipher.final('utf8')
    }

    try {
      const original = await readState()
      await wasm.revokeKey()
      const revoked = await readState()
      const iv = randomBytes(12)
      const cipher = createCipheriv('aes-256-gcm', wrap, iv)
      const ciphertext = Buffer.concat([
        cipher.update(revoked.replace(/,"revStateGen":0}$/, `,${metadata}}`), 'utf8'),
        cipher.final(),
      ])
      await fs.writeFile(
        statePath,
        [iv, cipher.getAuthTag(), ciphertext].map((part) => part.toString('base64')).join(':'),
      )
      await stale.rotateKey()
      const rotated = await readState()
      expect(rotated).toContain(metadata)
      const oldKeys: unknown = JSON.parse(original)
      const latestKeys: unknown = JSON.parse(revoked)
      const rotatedKeys: unknown = JSON.parse(rotated)
      expect(rotatedKeys).toHaveProperty('previous')
      function current(state: unknown): unknown {
        return typeof state === 'object' && state !== null && 'current' in state
          ? state.current
          : undefined
      }
      expect(rotatedKeys).toHaveProperty('previous', current(latestKeys))
      expect(rotatedKeys).not.toHaveProperty('previous', current(oldKeys))
    } finally {
      wrap.fill(0)
      wasm.dispose()
    }
  })

  it('permits only one rotation across competing WASM and TypeScript writers', async () => {
    env = await createCliTestEnv()
    const ts = await VaultKeeper.init({ configDir: env.configDir, skipDoctor: true })
    const wasm = await createVaultKeeper({ skipDoctor: true }, env.configDir)
    try {
      const results = await Promise.allSettled([ts.rotateKey(), wasm.rotateKey()])
      expect(results.filter((result) => result.status === 'fulfilled')).toHaveLength(1)
      expect(results.filter((result) => result.status === 'rejected')).toHaveLength(1)
    } finally {
      wasm.dispose()
    }
  })
})
