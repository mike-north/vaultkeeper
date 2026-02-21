import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { VaultKeeper } from '../../src/vault.js'
import { BackendRegistry } from '../../src/backend/registry.js'
import type { SecretBackend } from '../../src/backend/types.js'
import type { VaultConfig } from '../../src/types.js'
import { clearBlocklist } from '../../src/jwe/claims.js'
import { createInMemoryBackend } from '../helpers/backend.js'

function e2eConfig(): VaultConfig {
  return {
    version: 1,
    backends: [{ type: 'memory', enabled: true }],
    keyRotation: { gracePeriodDays: 7 },
    defaults: { ttlMinutes: 30, trustTier: 3 },
  }
}

// ---------------------------------------------------------------------------
// Full lifecycle: init → setup → authorize → getSecret → read
// ---------------------------------------------------------------------------

describe('VaultKeeper e2e lifecycle', () => {
  let backend: SecretBackend

  beforeEach(() => {
    clearBlocklist()
    backend = createInMemoryBackend()
    BackendRegistry.register('memory', () => backend)
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('should complete the full lifecycle: init → setup → authorize → getSecret → read', async () => {
    // Pre-populate the backend with a secret
    await backend.store('api-key', 'sk-live-abc123')

    // Init
    const vault = await VaultKeeper.init({
      skipDoctor: true,
      config: e2eConfig(),
      configDir: '/tmp/vk-e2e',
    })

    // Setup: create a JWE token for the secret
    const jwe = await vault.setup('api-key', { executablePath: 'dev' })
    expect(typeof jwe).toBe('string')

    // Authorize: decrypt and validate the token
    const { token, response } = await vault.authorize(jwe)
    expect(response.keyStatus).toBe('current')

    // GetSecret: read the secret value through the accessor
    const accessor = vault.getSecret(token)
    let secretValue = ''
    accessor.read((buf) => {
      secretValue = buf.toString('utf-8')
    })
    expect(secretValue).toBe('sk-live-abc123')
  })

  it('should handle multiple secrets independently', async () => {
    await backend.store('secret-a', 'value-a')
    await backend.store('secret-b', 'value-b')

    const vault = await VaultKeeper.init({
      skipDoctor: true,
      config: e2eConfig(),
      configDir: '/tmp/vk-e2e',
    })

    const jweA = await vault.setup('secret-a', { executablePath: 'dev' })
    const jweB = await vault.setup('secret-b', { executablePath: 'dev' })

    const { token: tokenA } = await vault.authorize(jweA)
    const { token: tokenB } = await vault.authorize(jweB)

    let valA = ''
    vault.getSecret(tokenA).read((buf) => {
      valA = buf.toString('utf-8')
    })

    let valB = ''
    vault.getSecret(tokenB).read((buf) => {
      valB = buf.toString('utf-8')
    })

    expect(valA).toBe('value-a')
    expect(valB).toBe('value-b')
  })

  it('should reject authorization after the JWE has been used beyond its limit', async () => {
    await backend.store('limited', 'one-time-value')

    const vault = await VaultKeeper.init({
      skipDoctor: true,
      config: e2eConfig(),
      configDir: '/tmp/vk-e2e',
    })

    const jwe = await vault.setup('limited', {
      executablePath: 'dev',
      useLimit: 2,
    })

    // First two authorizations succeed
    await vault.authorize(jwe)
    await vault.authorize(jwe)

    // Third should fail — token was blocked after reaching its use limit
    await expect(vault.authorize(jwe)).rejects.toThrow()
  })
})
