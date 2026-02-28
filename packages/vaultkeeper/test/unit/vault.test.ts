import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { VaultKeeper } from '../../src/vault.js'
import type { VaultConfig } from '../../src/types.js'
import { BackendRegistry } from '../../src/backend/registry.js'
import type { SecretBackend } from '../../src/backend/types.js'
import { clearBlocklist } from '../../src/jwe/claims.js'
import * as delegatedFetchModule from '../../src/access/delegated-fetch.js'
import * as delegatedExecModule from '../../src/access/delegated-exec.js'
import * as delegatedSignModule from '../../src/access/delegated-sign.js'
import * as delegatedVerifyModule from '../../src/access/delegated-verify.js'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function testConfig(): VaultConfig {
  return {
    version: 1,
    backends: [{ type: 'test', enabled: true }],
    keyRotation: { gracePeriodDays: 7 },
    defaults: { ttlMinutes: 60, trustTier: 3 },
  }
}

function createMockBackend(secrets: Record<string, string> = {}): SecretBackend {
  return {
    type: 'test',
    displayName: 'Test Backend',
    isAvailable: () => Promise.resolve(true),
    store: vi.fn((_id: string, _secret: string) => Promise.resolve()),
    retrieve: vi.fn((id: string) => {
      const val = secrets[id]
      if (val === undefined) {
        return Promise.reject(new Error(`Secret not found: ${id}`))
      }
      return Promise.resolve(val)
    }),
    delete: vi.fn(() => Promise.resolve()),
    exists: vi.fn((id: string) => Promise.resolve(id in secrets)),
  }
}

async function initVault(
  secrets: Record<string, string> = { 'my-secret': 'hunter2' },
): Promise<VaultKeeper> {
  const backend = createMockBackend(secrets)
  BackendRegistry.register('test', () => backend)

  return VaultKeeper.init({
    skipDoctor: true,
    config: testConfig(),
    configDir: '/tmp/vaultkeeper-test',
  })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('VaultKeeper', () => {
  beforeEach(() => {
    clearBlocklist()
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  describe('init', () => {
    it('should create a VaultKeeper instance with skipDoctor', async () => {
      const vault = await initVault()
      expect(vault).toBeInstanceOf(VaultKeeper)
    })
  })

  describe('doctor', () => {
    it('should return a preflight result', async () => {
      const result = await VaultKeeper.doctor()
      expect(result).toHaveProperty('ready')
      expect(result).toHaveProperty('checks')
      expect(result).toHaveProperty('warnings')
      expect(result).toHaveProperty('nextSteps')
    })
  })

  describe('setup + authorize lifecycle', () => {
    it('should create a JWE and authorize it', async () => {
      const vault = await initVault()
      const jwe = await vault.setup('my-secret', { executablePath: 'dev' })

      expect(typeof jwe).toBe('string')
      expect(jwe.split('.')).toHaveLength(5) // compact JWE

      const { token, response } = await vault.authorize(jwe)
      expect(token).toBeDefined()
      expect(response.keyStatus).toBe('current')
      expect(response.rotatedJwt).toBeUndefined()
    })

    it('should respect TTL override', async () => {
      const vault = await initVault()
      const jwe = await vault.setup('my-secret', {
        executablePath: 'dev',
        ttlMinutes: 5,
      })
      expect(typeof jwe).toBe('string')
    })

    it('should respect use limit', async () => {
      const vault = await initVault()
      const jwe = await vault.setup('my-secret', {
        executablePath: 'dev',
        useLimit: 1,
      })

      // First authorize succeeds
      await vault.authorize(jwe)

      // Second authorize should fail — the token was blocked after first use
      await expect(vault.authorize(jwe)).rejects.toThrow()
    })
  })

  describe('getSecret', () => {
    it('should return a SecretAccessor that yields the secret', async () => {
      const vault = await initVault()
      const jwe = await vault.setup('my-secret', { executablePath: 'dev' })
      const { token } = await vault.authorize(jwe)

      const accessor = vault.getSecret(token)
      let captured = ''
      accessor.read((buf) => {
        captured = buf.toString('utf-8')
      })
      expect(captured).toBe('hunter2')
    })
  })

  describe('rotateKey', () => {
    it('should rotate the key and provide rotatedJwt on authorize', async () => {
      const vault = await initVault()
      const jwe = await vault.setup('my-secret', { executablePath: 'dev' })

      await vault.rotateKey()

      const { response } = await vault.authorize(jwe)
      expect(response.keyStatus).toBe('previous')
      expect(response.rotatedJwt).toBeDefined()
      expect(typeof response.rotatedJwt).toBe('string')

      // The rotated JWE should work with current key
      const rotatedJwt = response.rotatedJwt
      expect(rotatedJwt).toBeDefined()
      if (rotatedJwt === undefined) throw new Error('unreachable')
      const { response: response2 } = await vault.authorize(rotatedJwt)
      expect(response2.keyStatus).toBe('current')
    })
  })

  describe('revokeKey', () => {
    it('should revoke the key making old JWEs unusable', async () => {
      const vault = await initVault()
      const jwe = await vault.setup('my-secret', { executablePath: 'dev' })

      await vault.revokeKey()

      await expect(vault.authorize(jwe)).rejects.toThrow()
    })
  })

  describe('setDevelopmentMode', () => {
    it('should add and remove executables from dev mode', async () => {
      const vault = await initVault()

      await vault.setDevelopmentMode('/usr/bin/node', true)
      // Setting again should be a no-op
      await vault.setDevelopmentMode('/usr/bin/node', true)

      // Remove
      await vault.setDevelopmentMode('/usr/bin/node', false)
      // Remove again should be a no-op
      await vault.setDevelopmentMode('/usr/bin/node', false)
    })
  })

  describe('fetch', () => {
    it('delegates to delegatedFetch and returns the response with current keyStatus', async () => {
      const vault = await initVault()
      const jwe = await vault.setup('my-secret', { executablePath: 'dev' })
      const { token } = await vault.authorize(jwe)

      const mockResponse = new Response('ok', { status: 200 })
      const fetchSpy = vi
        .spyOn(delegatedFetchModule, 'delegatedFetch')
        .mockResolvedValue(mockResponse)

      const { vaultResponse } = await vault.fetch(token, {
        url: 'https://example.com/api?key={{secret}}',
      })

      expect(fetchSpy).toHaveBeenCalledOnce()
      // The secret value should have been passed (not the placeholder)
      const [calledSecret] = fetchSpy.mock.calls[0] ?? []
      expect(calledSecret).toBe('hunter2')
      expect(vaultResponse.keyStatus).toBe('current')
    })
  })

  describe('exec', () => {
    it('delegates to delegatedExec and returns the result with current keyStatus', async () => {
      const vault = await initVault()
      const jwe = await vault.setup('my-secret', { executablePath: 'dev' })
      const { token } = await vault.authorize(jwe)

      const mockResult = { stdout: 'hunter2\n', stderr: '', exitCode: 0 }
      const execSpy = vi
        .spyOn(delegatedExecModule, 'delegatedExec')
        .mockResolvedValue(mockResult)

      const { result, vaultResponse } = await vault.exec(token, {
        command: 'echo',
        args: ['{{secret}}'],
      })

      expect(execSpy).toHaveBeenCalledOnce()
      expect(execSpy).toHaveBeenCalledWith('hunter2', expect.objectContaining({ command: 'echo' }))
      expect(result.exitCode).toBe(0)
      expect(vaultResponse.keyStatus).toBe('current')
    })
  })

  describe('sign', () => {
    it('delegates to delegatedSign and returns the result with current keyStatus', async () => {
      const vault = await initVault()
      const jwe = await vault.setup('my-secret', { executablePath: 'dev' })
      const { token } = await vault.authorize(jwe)

      const mockResult = { signature: 'c2lnbmF0dXJl', algorithm: 'ed25519' }
      const signSpy = vi
        .spyOn(delegatedSignModule, 'delegatedSign')
        .mockReturnValue(mockResult)

      const { result, vaultResponse } = await vault.sign(token, { data: 'test-data' })

      expect(signSpy).toHaveBeenCalledOnce()
      const [calledSecret] = signSpy.mock.calls[0] ?? []
      expect(calledSecret).toBe('hunter2')
      expect(result).toBe(mockResult)
      expect(vaultResponse.keyStatus).toBe('current')
    })
  })

  describe('verify', () => {
    it('delegates to delegatedVerify', () => {
      const verifySpy = vi
        .spyOn(delegatedVerifyModule, 'delegatedVerify')
        .mockReturnValue(true)

      const result = VaultKeeper.verify({
        data: 'test',
        signature: 'sig',
        publicKey: 'pem',
      })

      expect(verifySpy).toHaveBeenCalledOnce()
      expect(result).toBe(true)
    })
  })

  describe('negative cases', () => {
    it('should reject authorize with corrupted JWE', async () => {
      const vault = await initVault()
      await expect(vault.authorize('not.a.valid.jwe.token')).rejects.toThrow()
    })

    it('should reject setup for nonexistent secret', async () => {
      const vault = await initVault()
      await expect(
        vault.setup('nonexistent', { executablePath: 'dev' }),
      ).rejects.toThrow('Secret not found')
    })
  })
})
