import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { VaultKeeper } from '../../src/vault.js'
import { BackendRegistry } from '../../src/backend/registry.js'
import type { SecretBackend } from '../../src/backend/types.js'
import type { VaultConfig } from '../../src/types.js'
import { clearBlocklist } from '../../src/jwe/claims.js'
import { createInMemoryBackend } from '../helpers/backend.js'

function rotationConfig(): VaultConfig {
  return {
    version: 1,
    backends: [{ type: 'memory', enabled: true }],
    keyRotation: { gracePeriodDays: 7 },
    defaults: { ttlMinutes: 30, trustTier: 3 },
  }
}

// ---------------------------------------------------------------------------
// Key rotation e2e tests
// ---------------------------------------------------------------------------

describe('Key rotation e2e', () => {
  let backend: SecretBackend

  beforeEach(() => {
    clearBlocklist()
    backend = createInMemoryBackend()
    BackendRegistry.register('memory', () => backend)
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('should provide rotatedJwt when authorizing with old key after rotation', async () => {
    await backend.store('db-pass', 'pg-secret-123')

    const vault = await VaultKeeper.init({
      skipDoctor: true,
      config: rotationConfig(),
      configDir: '/tmp/vk-rotation',
    })

    // Setup with the original key
    const originalJwe = await vault.setup('db-pass', { executablePath: 'dev' })

    // Rotate the key
    await vault.rotateKey()

    // Authorize with the old JWE — should still work but indicate key is 'previous'
    const { token, response } = await vault.authorize(originalJwe)
    expect(response.keyStatus).toBe('previous')
    expect(response.rotatedJwt).toBeDefined()

    // The secret should still be accessible
    let secretValue = ''
    vault.getSecret(token).read((buf) => {
      secretValue = buf.toString('utf-8')
    })
    expect(secretValue).toBe('pg-secret-123')

    // The rotated JWE should work with the current key
    const rotatedJwt = response.rotatedJwt
    expect(rotatedJwt).toBeDefined()
    if (rotatedJwt === undefined) throw new Error('unreachable')
    const { response: newResponse } = await vault.authorize(rotatedJwt)
    expect(newResponse.keyStatus).toBe('current')
    expect(newResponse.rotatedJwt).toBeUndefined()
  })

  it('should reject old JWE after key revocation', async () => {
    await backend.store('api-token', 'tok-xyz')

    const vault = await VaultKeeper.init({
      skipDoctor: true,
      config: rotationConfig(),
      configDir: '/tmp/vk-rotation',
    })

    const jwe = await vault.setup('api-token', { executablePath: 'dev' })

    // Revoke
    await vault.revokeKey()

    // Old JWE should be rejected
    await expect(vault.authorize(jwe)).rejects.toThrow()
  })

  it('should allow new JWE after revocation', async () => {
    await backend.store('new-secret', 'fresh-value')

    const vault = await VaultKeeper.init({
      skipDoctor: true,
      config: rotationConfig(),
      configDir: '/tmp/vk-rotation',
    })

    await vault.revokeKey()

    // New setup with the new key should work
    const jwe = await vault.setup('new-secret', { executablePath: 'dev' })
    const { token, response } = await vault.authorize(jwe)
    expect(response.keyStatus).toBe('current')

    let val = ''
    vault.getSecret(token).read((buf) => {
      val = buf.toString('utf-8')
    })
    expect(val).toBe('fresh-value')
  })

  it('should handle double rotation attempt by throwing RotationInProgressError', async () => {
    await backend.store('secret', 'val')

    const vault = await VaultKeeper.init({
      skipDoctor: true,
      config: rotationConfig(),
      configDir: '/tmp/vk-rotation',
    })

    // First rotation succeeds
    await vault.rotateKey()

    // Second rotation should throw because grace period is still active
    await expect(vault.rotateKey()).rejects.toThrow(/rotation.*already in progress/i)

    // JWEs created after the first rotation should use the current key
    const jwe = await vault.setup('secret', { executablePath: 'dev' })
    const { response } = await vault.authorize(jwe)
    expect(response.keyStatus).toBe('current')
  })
})
