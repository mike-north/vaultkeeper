import { describe, it, expect, beforeEach } from 'vitest'
import { TestVault, InMemoryBackend } from '../../src/index.js'
import { SecretNotFoundError } from 'vaultkeeper'

describe('InMemoryBackend', () => {
  let backend: InMemoryBackend

  beforeEach(() => {
    backend = new InMemoryBackend()
  })

  it('should report as available', async () => {
    expect(await backend.isAvailable()).toBe(true)
  })

  it('should store and retrieve a secret', async () => {
    await backend.store('key1', 'value1')
    expect(await backend.retrieve('key1')).toBe('value1')
  })

  it('should reject retrieval of nonexistent secret with SecretNotFoundError', async () => {
    // Regression: previously threw a plain Error, not SecretNotFoundError.
    // Code that catches SecretNotFoundError in production would behave differently
    // from tests using InMemoryBackend.
    const err = await backend.retrieve('missing').catch((e: unknown) => e)
    expect(err).toBeInstanceOf(SecretNotFoundError)
    if (err instanceof SecretNotFoundError) {
      expect(err.message).toBe('Secret not found: missing')
    }
  })

  it('should delete a secret', async () => {
    await backend.store('key1', 'value1')
    await backend.delete('key1')
    expect(await backend.exists('key1')).toBe(false)
  })

  it('should check existence', async () => {
    expect(await backend.exists('key1')).toBe(false)
    await backend.store('key1', 'value1')
    expect(await backend.exists('key1')).toBe(true)
  })

  it('should clear all secrets', async () => {
    await backend.store('a', '1')
    await backend.store('b', '2')
    expect(backend.size).toBe(2)
    backend.clear()
    expect(backend.size).toBe(0)
  })

  it('should report correct size', async () => {
    expect(backend.size).toBe(0)
    await backend.store('a', '1')
    expect(backend.size).toBe(1)
  })

  it('should have correct type and displayName', () => {
    expect(backend.type).toBe('memory')
    expect(backend.displayName).toBe('In-Memory Backend')
  })
})

describe('TestVault', () => {
  let vault: TestVault

  beforeEach(async () => {
    vault = await TestVault.create()
  })

  it('should create successfully', () => {
    expect(vault.keeper).toBeDefined()
    expect(vault.backend).toBeInstanceOf(InMemoryBackend)
  })

  it('should store and retrieve secrets through the full vault flow', async () => {
    await vault.store('test-secret', 'my-secret-value')
    const jwe = await vault.setup('test-secret')
    expect(typeof jwe).toBe('string')
    expect(jwe.length).toBeGreaterThan(0)

    const { token, vaultResponse } = await vault.keeper.authorize(jwe)
    expect(token).toBeDefined()
    expect(vaultResponse.keyStatus).toBe('current')
  })

  it('should support custom TTL', async () => {
    const customVault = await TestVault.create({ ttlMinutes: 1 })
    expect(customVault.keeper).toBeDefined()
  })

  it('should reset by clearing the backend', async () => {
    await vault.backend.store('s1', 'v1')
    expect(vault.backend.size).toBe(1)
    vault.reset()
    expect(vault.backend.size).toBe(0)
  })

  it('should fail to setup with nonexistent secret', async () => {
    await expect(vault.setup('nonexistent')).rejects.toThrow()
  })

  describe('setup() convenience method', () => {
    // The passthrough defaults to the development-only skipTrust opt-out so
    // consumer tests stay hermetic without naming a real executable to hash.
    it('mints a JWE for a stored secret without a trust choice (defaults to skipTrust)', async () => {
      await vault.store('conv-secret', 'conv-value')
      const jwe = await vault.setup('conv-secret')
      expect(jwe.split('.')).toHaveLength(5)
      const { token } = await vault.keeper.authorize(jwe)
      expect(token).toBeDefined()
    })

    it('passes an explicit skipTrust choice through to the keeper', async () => {
      await vault.store('conv-secret', 'conv-value')
      const jwe = await vault.setup('conv-secret', { skipTrust: true, ttlMinutes: 1 })
      expect(typeof jwe).toBe('string')
    })

    // Regression for PR #131 review thread 3588295526: `skipTrust: false` is
    // not an explicit trust choice — VaultKeeper only treats `skipTrust ===
    // true` as one. Previously `options?.skipTrust !== undefined` treated the
    // presence of the key (even when `false`) as "the caller chose", so this
    // call skipped the convenience default and forwarded `{ skipTrust: false }`
    // unchanged, which made the keeper throw ExecutableTrustRequiredError
    // instead of minting a token like full omission does.
    it('treats skipTrust: false as no choice, applying the convenience default like omission', async () => {
      await vault.store('conv-secret', 'conv-value')
      const jwe = await vault.setup('conv-secret', { skipTrust: false })
      expect(jwe.split('.')).toHaveLength(5)
      const { token } = await vault.keeper.authorize(jwe)
      expect(token).toBeDefined()
    })

    // Regression for the same thread: when an executablePath IS supplied
    // alongside skipTrust: false, that is a real choice and must be passed
    // through unchanged so verification runs normally (not silently skipped).
    it('runs verification normally when skipTrust: false is paired with an executablePath', async () => {
      await vault.store('conv-secret', 'conv-value')
      await expect(
        vault.setup('conv-secret', {
          skipTrust: false,
          executablePath: '/nonexistent/dev-only-tool',
        }),
      ).rejects.toThrow()
    })
  })

  describe('store() convenience method', () => {
    it('stores a secret accessible through the full vault flow', async () => {
      await vault.store('conv-secret', 'conv-value')
      const jwe = await vault.setup('conv-secret')
      const { token, vaultResponse } = await vault.keeper.authorize(jwe)
      expect(token).toBeDefined()
      expect(vaultResponse.keyStatus).toBe('current')
    })

    it('delegates to backend.store()', async () => {
      await vault.store('delegate-test', 'some-value')
      expect(await vault.backend.retrieve('delegate-test')).toBe('some-value')
    })
  })

  describe('delete() convenience method', () => {
    it('removes a previously stored secret', async () => {
      await vault.store('to-delete', 'val')
      expect(await vault.backend.exists('to-delete')).toBe(true)
      await vault.delete('to-delete')
      expect(await vault.backend.exists('to-delete')).toBe(false)
    })

    it('does not throw when deleting a nonexistent secret', async () => {
      await expect(vault.delete('nonexistent')).resolves.toBeUndefined()
    })
  })
})
