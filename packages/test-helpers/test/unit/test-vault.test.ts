import { describe, it, expect, beforeEach } from 'vitest'
import { TestVault, InMemoryBackend } from '../../src/index.js'

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

  it('should reject retrieval of nonexistent secret', async () => {
    await expect(backend.retrieve('missing')).rejects.toThrow('Secret not found: missing')
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
    await vault.backend.store('test-secret', 'my-secret-value')
    const jwe = await vault.keeper.setup('test-secret')
    expect(typeof jwe).toBe('string')
    expect(jwe.length).toBeGreaterThan(0)

    const { token, response } = await vault.keeper.authorize(jwe)
    expect(token).toBeDefined()
    expect(response.keyStatus).toBe('current')
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
    await expect(vault.keeper.setup('nonexistent')).rejects.toThrow()
  })
})
