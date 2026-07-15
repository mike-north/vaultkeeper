import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { VaultKeeper } from '../../src/vault.js'
import type { VaultConfig } from '../../src/types.js'
import { BackendRegistry } from '../../src/backend/registry.js'
import type { SecretBackend } from '../../src/backend/types.js'
import { clearBlocklist } from '../../src/jwe/claims.js'
import { UsageLimitExceededError } from '../../src/errors.js'
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

/** A `SecretBackend` backed by a real `Map`, so store() output is visible to retrieve(). */
function createStatefulMockBackend(): SecretBackend {
  const store = new Map<string, string>()
  return {
    type: 'test',
    displayName: 'Stateful Test Backend',
    isAvailable: () => Promise.resolve(true),
    store: (id: string, secret: string) => {
      store.set(id, secret)
      return Promise.resolve()
    },
    retrieve: (id: string) => {
      const val = store.get(id)
      if (val === undefined) {
        return Promise.reject(new Error(`Secret not found: ${id}`))
      }
      return Promise.resolve(val)
    },
    delete: (id: string) => {
      store.delete(id)
      return Promise.resolve()
    },
    exists: (id: string) => Promise.resolve(store.has(id)),
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
    // Clear auto-registered builtins so tests can register their own mock backend
    BackendRegistry.clearBackends()
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

  describe('activeBackendType', () => {
    it('should expose the type of the first enabled backend', async () => {
      const vault = await initVault()
      expect(vault.activeBackendType).toBe('test')
    })

    it('should reflect the first enabled backend when several are configured', async () => {
      const backend = createMockBackend()
      BackendRegistry.register('test', () => backend)
      const vault = await VaultKeeper.init({
        skipDoctor: true,
        configDir: '/tmp/vaultkeeper-test',
        config: {
          version: 1,
          backends: [
            { type: 'disabled-first', enabled: false },
            { type: 'test', enabled: true },
          ],
          keyRotation: { gracePeriodDays: 7 },
          defaults: { ttlMinutes: 60, trustTier: 3 },
        },
      })
      expect(vault.activeBackendType).toBe('test')
    })

    // Introspection must not instantiate the backend: reading the type of an
    // unregistered/unavailable backend returns its configured type instead of
    // throwing (thread 3582762757 — a getter that called #requireBackend()
    // would have thrown here).
    it('should return the configured type without instantiating an unregistered backend', async () => {
      // No BackendRegistry.register('unregistered-backend', ...) — the type is
      // not registered, so instantiating it would throw.
      const vault = await VaultKeeper.init({
        skipDoctor: true,
        configDir: '/tmp/vaultkeeper-test',
        config: {
          version: 1,
          backends: [{ type: 'unregistered-backend', enabled: true }],
          keyRotation: { gracePeriodDays: 7 },
          defaults: { ttlMinutes: 60, trustTier: 3 },
        },
      })
      expect(vault.activeBackendType).toBe('unregistered-backend')
    })
  })

  describe('init with backend option', () => {
    it('initializes without registering a backend in BackendRegistry', async () => {
      // No BackendRegistry.register() call anywhere in this test — the
      // injected backend must be usable without global registration.
      const backend = createMockBackend({ 'my-secret': 'hunter2' })

      const vault = await VaultKeeper.init({ skipDoctor: true, backend })

      expect(vault).toBeInstanceOf(VaultKeeper)
    })

    it('round-trips a store/retrieve through the injected backend', async () => {
      // A stateful backend (unlike createMockBackend's fixed secrets map) so
      // the test proves store() output is actually visible to retrieve() —
      // not just that store() was called.
      const backend = createStatefulMockBackend()
      const vault = await VaultKeeper.init({ skipDoctor: true, backend })

      await vault.store('injected-secret', 'injected-value')

      const retrieved = await backend.retrieve('injected-secret')
      expect(retrieved).toBe('injected-value')

      const jwe = await vault.setup('injected-secret', { skipTrust: true })
      const { token } = await vault.authorize(jwe)
      const accessor = vault.getSecret(token)
      let captured = ''
      accessor.read((buf) => {
        captured = buf.toString('utf-8')
      })
      expect(captured).toBe('injected-value')
    })

    it('uses a minimal built-in default config when config is omitted', async () => {
      const backend = createMockBackend({ 'my-secret': 'hunter2' })
      // No `config` or `configDir`-loadable file is supplied — this only
      // works because init() falls back to a built-in default config when
      // `backend` is set, instead of calling loadConfig().
      const vault = await VaultKeeper.init({ skipDoctor: true, backend })

      const jwe = await vault.setup('my-secret', { skipTrust: true })
      expect(typeof jwe).toBe('string')
    })

    it('does not share/mutate config between two instances created with the backend option', async () => {
      // Regression: init() previously reused a single shared
      // DEFAULT_INJECTED_BACKEND_CONFIG object whenever `backend` was set
      // without `config`, so mutating one instance's config (e.g. via
      // setDevelopmentMode()) leaked into every other instance created the
      // same way.
      const vault1 = await VaultKeeper.init({
        skipDoctor: true,
        backend: createMockBackend({ 'my-secret': 'hunter2' }),
      })
      const vault2 = await VaultKeeper.init({
        skipDoctor: true,
        backend: createMockBackend({ 'my-secret': 'hunter2' }),
      })

      // Add a nonexistent path to vault1's dev-mode allowlist only.
      await vault1.setDevelopmentMode('/nonexistent/dev-only-tool', true)

      // vault2 must not see vault1's dev-mode entry: since the path isn't
      // 'dev' and isn't on vault2's own allowlist, setup() must attempt real
      // identity verification and fail because the file doesn't exist.
      await expect(
        vault2.setup('my-secret', { executablePath: '/nonexistent/dev-only-tool' }),
      ).rejects.toThrow()

      // vault1, which explicitly enabled dev mode for that path, must still succeed.
      const jwe = await vault1.setup('my-secret', {
        executablePath: '/nonexistent/dev-only-tool',
      })
      expect(typeof jwe).toBe('string')
    })

    it('precedence: backend option wins over config.backends resolution', async () => {
      // A different backend is registered under the type named in
      // testConfig() ('test'), but it must never be consulted because
      // `backend` takes precedence over BackendRegistry/config.backends.
      const registryRetrieveSpy = vi.fn((id: string) => Promise.resolve(`from-registry:${id}`))
      const registryBackend = createMockBackend({ 'my-secret': 'from-registry' })
      registryBackend.retrieve = registryRetrieveSpy
      BackendRegistry.register('test', () => registryBackend)

      const injectedBackend = createMockBackend({ 'my-secret': 'from-injected' })
      const vault = await VaultKeeper.init({
        skipDoctor: true,
        config: testConfig(),
        configDir: '/tmp/vaultkeeper-test',
        backend: injectedBackend,
      })

      const jwe = await vault.setup('my-secret', { skipTrust: true })
      const { token } = await vault.authorize(jwe)
      const accessor = vault.getSecret(token)
      let captured = ''
      accessor.read((buf) => {
        captured = buf.toString('utf-8')
      })

      expect(captured).toBe('from-injected')
      expect(registryRetrieveSpy).not.toHaveBeenCalled()
    })

    it('precedence: other config fields (e.g. defaults.ttlMinutes) still apply with backend set', async () => {
      const backend = createMockBackend({ 'my-secret': 'hunter2' })
      const config = testConfig()
      config.defaults.ttlMinutes = 5

      const vault = await VaultKeeper.init({
        skipDoctor: true,
        config,
        backend,
      })

      // ttlMinutes from the supplied config is used even though the backend
      // resolution itself is overridden by the `backend` option.
      const jwe = await vault.setup('my-secret', { skipTrust: true })
      expect(typeof jwe).toBe('string')
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
      const jwe = await vault.setup('my-secret', { skipTrust: true })

      expect(typeof jwe).toBe('string')
      expect(jwe.split('.')).toHaveLength(5) // compact JWE

      const { token, vaultResponse } = await vault.authorize(jwe)
      expect(token).toBeDefined()
      expect(vaultResponse.keyStatus).toBe('current')
      expect(vaultResponse.rotatedJwt).toBeUndefined()
    })

    it('should respect TTL override', async () => {
      const vault = await initVault()
      const jwe = await vault.setup('my-secret', {
        skipTrust: true,
        ttlMinutes: 5,
      })
      expect(typeof jwe).toBe('string')
    })

    it('should respect use limit — throws UsageLimitExceededError after limit reached', async () => {
      const vault = await initVault()
      const jwe = await vault.setup('my-secret', {
        skipTrust: true,
        useLimit: 1,
      })

      // First authorize succeeds
      await vault.authorize(jwe)

      // Second authorize must throw UsageLimitExceededError, not TokenRevokedError.
      // Regression: previously the token was added to the blocklist on first use,
      // causing the second call to throw TokenRevokedError instead.
      await expect(vault.authorize(jwe)).rejects.toThrow(UsageLimitExceededError)
    })

    it('should throw UsageLimitExceededError (not TokenRevokedError) for use=2 after second use', async () => {
      const vault = await initVault()
      const jwe = await vault.setup('my-secret', {
        skipTrust: true,
        useLimit: 2,
      })

      // First two authorizations succeed
      await vault.authorize(jwe)
      await vault.authorize(jwe)

      // Third call must be UsageLimitExceededError
      const err = await vault.authorize(jwe).catch((e: unknown) => e)
      expect(err).toBeInstanceOf(UsageLimitExceededError)
    })
  })

  describe('getSecret', () => {
    it('should return a SecretAccessor that yields the secret', async () => {
      const vault = await initVault()
      const jwe = await vault.setup('my-secret', { skipTrust: true })
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
      const jwe = await vault.setup('my-secret', { skipTrust: true })

      await vault.rotateKey()

      const { vaultResponse } = await vault.authorize(jwe)
      expect(vaultResponse.keyStatus).toBe('previous')
      expect(vaultResponse.rotatedJwt).toBeDefined()
      expect(typeof vaultResponse.rotatedJwt).toBe('string')

      // The rotated JWE should work with current key
      const rotatedJwt = vaultResponse.rotatedJwt
      expect(rotatedJwt).toBeDefined()
      if (rotatedJwt === undefined) throw new Error('unreachable')
      const { vaultResponse: vaultResponse2 } = await vault.authorize(rotatedJwt)
      expect(vaultResponse2.keyStatus).toBe('current')
    })
  })

  describe('revokeKey', () => {
    it('should revoke the key making old JWEs unusable', async () => {
      const vault = await initVault()
      const jwe = await vault.setup('my-secret', { skipTrust: true })

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
      const jwe = await vault.setup('my-secret', { skipTrust: true })
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
      const jwe = await vault.setup('my-secret', { skipTrust: true })
      const { token } = await vault.authorize(jwe)

      const mockResult = { stdout: 'hunter2\n', stderr: '', exitCode: 0 }
      const execSpy = vi.spyOn(delegatedExecModule, 'delegatedExec').mockResolvedValue(mockResult)

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
      const jwe = await vault.setup('my-secret', { skipTrust: true })
      const { token } = await vault.authorize(jwe)

      const mockResult = { signature: 'c2lnbmF0dXJl', algorithm: 'ed25519' }
      const signSpy = vi.spyOn(delegatedSignModule, 'delegatedSign').mockReturnValue(mockResult)

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
      const verifySpy = vi.spyOn(delegatedVerifyModule, 'delegatedVerify').mockReturnValue(true)

      const result = VaultKeeper.verify({
        data: 'test',
        signature: 'sig',
        publicKey: 'pem',
      })

      expect(verifySpy).toHaveBeenCalledOnce()
      expect(result).toBe(true)
    })
  })

  describe('store', () => {
    it('should delegate to the active backend', async () => {
      const storeSpy = vi.fn(() => Promise.resolve())
      const backend = createMockBackend()
      backend.store = storeSpy
      BackendRegistry.register('test', () => backend)

      const vault = await VaultKeeper.init({
        skipDoctor: true,
        config: testConfig(),
        configDir: '/tmp/vaultkeeper-test',
      })
      await vault.store('new-secret', 'new-value')
      expect(storeSpy).toHaveBeenCalledWith('new-secret', 'new-value')
    })
  })

  describe('delete', () => {
    it('should delegate to the active backend', async () => {
      const deleteSpy = vi.fn(() => Promise.resolve())
      const backend = createMockBackend({ 'my-secret': 'hunter2' })
      backend.delete = deleteSpy
      BackendRegistry.register('test', () => backend)

      const vault = await VaultKeeper.init({
        skipDoctor: true,
        config: testConfig(),
        configDir: '/tmp/vaultkeeper-test',
      })
      await vault.delete('my-secret')
      expect(deleteSpy).toHaveBeenCalledWith('my-secret')
    })
  })

  // secretExists() backs the CLI's issue #69 fix: exec validates secret
  // existence BEFORE the interactivity/TTY gate, so it needs a way to check
  // existence without minting a token or touching the TOFU trust manifest.
  describe('secretExists', () => {
    it('should return true when the secret exists', async () => {
      const vault = await initVault({ 'my-secret': 'hunter2' })
      await expect(vault.secretExists('my-secret')).resolves.toBe(true)
    })

    it('should return false when the secret does not exist', async () => {
      const vault = await initVault({ 'my-secret': 'hunter2' })
      await expect(vault.secretExists('nonexistent')).resolves.toBe(false)
    })

    it('should delegate to the active backend without retrieving the value', async () => {
      const existsSpy = vi.fn(() => Promise.resolve(true))
      const retrieveSpy = vi.fn(() => Promise.reject(new Error('should not be called')))
      const backend = createMockBackend({ 'my-secret': 'hunter2' })
      backend.exists = existsSpy
      backend.retrieve = retrieveSpy
      BackendRegistry.register('test', () => backend)

      const vault = await VaultKeeper.init({
        skipDoctor: true,
        config: testConfig(),
        configDir: '/tmp/vaultkeeper-test',
      })
      await vault.secretExists('my-secret')
      expect(existsSpy).toHaveBeenCalledWith('my-secret')
      expect(retrieveSpy).not.toHaveBeenCalled()
    })

    it('should reject an empty name, same as store/delete', async () => {
      const vault = await initVault()
      await expect(vault.secretExists('')).rejects.toThrow('Secret name must not be empty')
    })
  })

  describe('negative cases', () => {
    it('should reject authorize with corrupted JWE', async () => {
      const vault = await initVault()
      await expect(vault.authorize('not.a.valid.jwe.token')).rejects.toThrow()
    })

    it('should reject setup for nonexistent secret', async () => {
      const vault = await initVault()
      await expect(vault.setup('nonexistent', { skipTrust: true })).rejects.toThrow(
        'Secret not found',
      )
    })

    it('should reject store with empty secret name', async () => {
      const vault = await initVault()
      await expect(vault.store('', 'value')).rejects.toThrow('Secret name must not be empty')
    })

    it('should reject store with whitespace-only secret name', async () => {
      const vault = await initVault()
      await expect(vault.store('   ', 'value')).rejects.toThrow('Secret name must not be empty')
    })

    it('should reject delete with empty secret name', async () => {
      const vault = await initVault()
      await expect(vault.delete('')).rejects.toThrow('Secret name must not be empty')
    })

    it('should reject setup with empty secret name', async () => {
      const vault = await initVault()
      await expect(vault.setup('', { skipTrust: true })).rejects.toThrow(
        'Secret name must not be empty',
      )
    })
  })
})
