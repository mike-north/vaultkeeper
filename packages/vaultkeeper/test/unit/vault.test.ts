import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { VaultKeeper } from '../../src/vault.js'
import type { VaultConfig } from '../../src/types.js'
import { BackendRegistry } from '../../src/backend/registry.js'
import type { SecretBackend } from '../../src/backend/types.js'
import { clearBlocklist } from '../../src/jwe/claims.js'
import {
  UsageLimitExceededError,
  AuthorizationDeniedError,
  SigningNotSupportedError,
  InvalidKeyMaterialError,
  VaultError,
} from '../../src/errors.js'
import * as jweTokenModule from '../../src/jwe/token.js'
import * as delegatedFetchModule from '../../src/access/delegated-fetch.js'
import * as delegatedExecModule from '../../src/access/delegated-exec.js'
import * as crypto from 'node:crypto'
import { CompactSign } from 'jose'

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

    // Regression for #167: with a backend injected via init({ backend }), the
    // config-driven enabled-backend list is empty, so the getter must report
    // the injected instance's declared `type` instead of throwing
    // BackendUnavailableError('none-enabled').
    it('returns the injected backend type instead of throwing (issue #167)', async () => {
      const backend = createStatefulMockBackend() // declares type 'test'
      const vault = await VaultKeeper.init({ backend, skipDoctor: true })

      // The bug: this getter threw BackendUnavailableError before the fix.
      expect(vault.activeBackendType).toBe('test')

      // Store/retrieve still work against the same injected instance.
      await vault.store('S', 'v')
      expect(await backend.retrieve('S')).toBe('v')
    })

    // Edge case for #167 AC #1: an injected backend that declares an empty
    // type falls back to the stable 'custom' sentinel rather than returning ''.
    it('falls back to the "custom" sentinel for an injected backend with an empty type (issue #167)', async () => {
      const backend: SecretBackend = {
        type: '',
        displayName: 'Anonymous Backend',
        isAvailable: () => Promise.resolve(true),
        store: () => Promise.resolve(),
        retrieve: () => Promise.resolve(''),
        delete: () => Promise.resolve(),
        exists: () => Promise.resolve(false),
      }
      const vault = await VaultKeeper.init({ backend, skipDoctor: true })
      expect(vault.activeBackendType).toBe('custom')
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

    // Regression for #167 follow-up (thread 3590033605): an injected backend
    // that declares an empty type must still mint a USABLE token. setup()
    // derives the `bkd` claim from the same centralized hint as
    // activeBackendType, so the empty type falls back to 'custom' — a non-empty
    // bkd that validateClaims accepts. Before the fix, bkd was '' and
    // authorize() threw "Invalid token: bkd must not be empty".
    it('mints a valid token (bkd="custom") for an injected empty-type backend (issue #167)', async () => {
      const backend: SecretBackend = {
        type: '', // empty declared type — the documented injected edge case
        displayName: 'Anonymous Backend',
        isAvailable: () => Promise.resolve(true),
        store: () => Promise.resolve(),
        retrieve: () => Promise.resolve('injected-value'),
        delete: () => Promise.resolve(),
        exists: () => Promise.resolve(true),
      }
      const vault = await VaultKeeper.init({ backend, skipDoctor: true })

      // Spy (call-through) to capture the claims actually minted, without
      // replacing the real token so authorize() still validates end-to-end.
      const createTokenSpy = vi.spyOn(jweTokenModule, 'createToken')

      // No options.backendType: setup() must derive a non-empty bkd on its own.
      const jwe = await vault.setup('injected-secret', { skipTrust: true })

      expect(createTokenSpy).toHaveBeenCalledOnce()
      expect(createTokenSpy.mock.calls[0]?.[1].bkd).toBe('custom')

      // The token round-trips: authorize() accepts it (pre-fix it threw on the
      // empty bkd) and the secret is recoverable.
      const { token } = await vault.authorize(jwe)
      const accessor = vault.getSecret(token)
      const secret = accessor.read((buf) => buf.toString('utf8'))
      expect(secret).toBe('injected-value')

      createTokenSpy.mockRestore()
    })

    // Regression for the review thread on #resolveBackendTypeHint (comment
    // 3590126933): a blank options.backendType override must not be treated
    // as authoritative — honoring it would mint a token with a blank `bkd`
    // claim that validateClaims later rejects (an unusable token). A blank
    // override falls through to the same declared-type/'custom' derivation
    // as no override at all. Before the fix, bkd was '  ' here.
    it('ignores a whitespace-only options.backendType override instead of minting a blank bkd claim', async () => {
      const backend: SecretBackend = {
        type: 'file',
        displayName: 'File Backend',
        isAvailable: () => Promise.resolve(true),
        store: () => Promise.resolve(),
        retrieve: () => Promise.resolve('injected-value'),
        delete: () => Promise.resolve(),
        exists: () => Promise.resolve(true),
      }
      const vault = await VaultKeeper.init({ backend, skipDoctor: true })

      const createTokenSpy = vi.spyOn(jweTokenModule, 'createToken')

      const jwe = await vault.setup('injected-secret', {
        skipTrust: true,
        backendType: '  ',
      })

      expect(createTokenSpy).toHaveBeenCalledOnce()
      expect(createTokenSpy.mock.calls[0]?.[1].bkd).toBe('file')

      // The token stays usable end-to-end.
      const { token } = await vault.authorize(jwe)
      const accessor = vault.getSecret(token)
      expect(accessor.read((buf) => buf.toString('utf8'))).toBe('injected-value')

      createTokenSpy.mockRestore()
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

  describe('signing keys on a non-signing backend', () => {
    // AC8: a backend that does not implement the signing contract must fail
    // with a typed SigningNotSupportedError naming the backends that do —
    // never a silent emulation. The mock 'test' backend has no signing methods.
    it('createSigningKey throws SigningNotSupportedError naming file backend', async () => {
      const vault = await initVault()
      await expect(vault.createSigningKey('k', 'EdDSA')).rejects.toBeInstanceOf(
        SigningNotSupportedError,
      )
      await expect(vault.createSigningKey('k', 'EdDSA')).rejects.toMatchObject({
        backendType: 'test',
        builtInSigningBackends: ['file'],
      })
    })

    it('exportPublicKey throws SigningNotSupportedError', async () => {
      const vault = await initVault()
      await expect(vault.exportPublicKey('k')).rejects.toBeInstanceOf(SigningNotSupportedError)
    })

    it('authorizeSigningKey throws SigningNotSupportedError', async () => {
      const vault = await initVault()
      await expect(vault.authorizeSigningKey('k')).rejects.toBeInstanceOf(SigningNotSupportedError)
    })
  })

  describe('signing-key name validation names the signing-key resource', () => {
    // The error must name what the caller actually passed — a bad signing-key
    // name must not be reported as a "secret" name.
    it('createSigningKey rejects an empty name with a signing-key message', async () => {
      const vault = await initVault()
      await expect(vault.createSigningKey('', 'EdDSA')).rejects.toThrow(
        'Signing key name must not be empty',
      )
    })

    it('exportPublicKey rejects a whitespace-only name with a signing-key message', async () => {
      const vault = await initVault()
      await expect(vault.exportPublicKey('   ')).rejects.toThrow(
        'Signing key name must not be empty',
      )
    })

    it('authorizeSigningKey rejects an empty name with a signing-key message', async () => {
      const vault = await initVault()
      await expect(vault.authorizeSigningKey('')).rejects.toThrow(
        'Signing key name must not be empty',
      )
    })
  })

  describe('sign rejects a non-signing token', () => {
    // AC3 defense in depth: sign() requires a signing-key capability token.
    // An ordinary secret token (from authorize()) must be rejected before any
    // signing happens.
    it('sign() with a secret token throws AuthorizationDeniedError', async () => {
      const vault = await initVault()
      const jwe = await vault.setup('my-secret', { skipTrust: true })
      const { token } = await vault.authorize(jwe)

      await expect(vault.sign(token, { payload: 'test-data' })).rejects.toBeInstanceOf(
        AuthorizationDeniedError,
      )
    })
  })

  describe('verify (offline, static)', () => {
    // Produce a detached compact JWS with jose (b64:false, crit:["b64"],
    // alg EdDSA) so verify() is exercised against an independently-produced
    // signature — not vaultkeeper's own signing path.
    async function makeDetachedJws(
      payload: string,
    ): Promise<{ jws: string; publicKeyPem: string }> {
      const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519')
      const jws = await new CompactSign(Buffer.from(payload, 'utf8'))
        .setProtectedHeader({ alg: 'EdDSA', b64: false, crit: ['b64'] })
        .sign(privateKey)
      return { jws, publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString() }
    }

    it('returns true for a valid detached signature', async () => {
      const payload = 'gate1:abc123:1706000000'
      const { jws, publicKeyPem } = await makeDetachedJws(payload)
      await expect(VaultKeeper.verify({ payload, jws, publicKey: publicKeyPem })).resolves.toBe(
        true,
      )
    })

    it('returns false for a tampered payload', async () => {
      const { jws, publicKeyPem } = await makeDetachedJws('original')
      await expect(
        VaultKeeper.verify({ payload: 'tampered', jws, publicKey: publicKeyPem }),
      ).resolves.toBe(false)
    })

    it('returns false for a structurally malformed JWS', async () => {
      const { publicKeyPem } = await makeDetachedJws('x')
      await expect(
        VaultKeeper.verify({ payload: 'x', jws: 'not-a-jws', publicKey: publicKeyPem }),
      ).resolves.toBe(false)
    })

    it('throws InvalidKeyMaterialError for an unparseable public key', async () => {
      const { jws } = await makeDetachedJws('x')
      await expect(
        VaultKeeper.verify({ payload: 'x', jws, publicKey: 'not-a-pem' }),
      ).rejects.toBeInstanceOf(InvalidKeyMaterialError)
    })

    it('throws InvalidKeyMaterialError when a private key is supplied as the public key', async () => {
      const { privateKey } = crypto.generateKeyPairSync('ed25519')
      const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString()
      const { jws } = await makeDetachedJws('x')
      await expect(
        VaultKeeper.verify({ payload: 'x', jws, publicKey: privatePem }),
      ).rejects.toBeInstanceOf(InvalidKeyMaterialError)
    })
  })

  describe('reserved-namespace integrity (the signing-key: prefix)', () => {
    // A library caller must not be able to store a secret whose name lands in
    // the reserved signing-key namespace — that would breach the documented
    // "a secret and a signing key can never collide under one name" guarantee.
    // Name-creating/binding paths reject ':'; read/delete paths stay permissive
    // so a legacy ':' secret remains reachable.
    it('store rejects a name containing ":" with a typed error naming the reserved namespace', async () => {
      const vault = await initVault()
      await expect(vault.store('signing-key:foo', 'v')).rejects.toBeInstanceOf(VaultError)
      await expect(vault.store('signing-key:foo', 'v')).rejects.toThrow(
        /reserved internal namespace/,
      )
    })

    it('setup rejects a name containing ":"', async () => {
      const vault = await initVault()
      await expect(vault.setup('signing-key:foo', { skipTrust: true })).rejects.toThrow(
        /must not contain ':'/,
      )
    })

    it('createSigningKey cannot escape its prefix via a crafted ":" name', async () => {
      // The name check runs before the signing backend is even resolved, so a
      // ':' name is rejected outright — a crafted name cannot reshape the
      // signing-key:<name> id it is prefixed into.
      const vault = await initVault()
      await expect(vault.createSigningKey('foo:bar', 'EdDSA')).rejects.toThrow(
        /must not contain ':'/,
      )
    })

    it('delete and secretExists stay permissive for a legacy ":" secret name', async () => {
      // Seed a legacy secret whose name contains ':' directly through the
      // backend (simulating data written before this rule existed).
      const vault = await initVault({ 'signing-key:legacy': 'legacy-value' })
      await expect(vault.secretExists('signing-key:legacy')).resolves.toBe(true)
      await expect(vault.delete('signing-key:legacy')).resolves.toBeUndefined()
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
