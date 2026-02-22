# vaultkeeper — AI Assistant Instructions

This document is written for AI assistants helping humans use the vaultkeeper library. It describes the API accurately, specifies which patterns to recommend, which to avoid, how to debug common errors, and which security constraints must be enforced in any generated code.

---

## 1. Project Overview

vaultkeeper is a TypeScript library providing unified, policy-enforced secret storage across OS credential backends. It ships as two packages in a pnpm workspace monorepo:

- **`vaultkeeper`** — the main library. Provides the `VaultKeeper` class, all backend implementations, JWE token lifecycle, identity verification, and the three access patterns (delegated fetch, delegated exec, controlled direct).
- **`@vaultkeeper/test-helpers`** — test utilities. Provides `InMemoryBackend` and `TestVault` for fast, hermetic tests that never touch the OS credential store.

The library is ESM-first. Its sole runtime dependency is `jose` (JWE/JWT). Everything else is dev-only. The public API is validated by API Extractor and all exports flow through `packages/vaultkeeper/src/index.ts`.

**Core model.** vaultkeeper never hands a raw secret string to application code directly. Instead it follows a three-step protocol:

1. `setup()` — read a secret from a backend and wrap it in a JWE token (compact encrypted string).
2. `authorize()` — decrypt the JWE, validate claims (expiry, usage limit, blocklist), verify the caller's executable identity, and return an opaque `CapabilityToken`.
3. Access — use the capability token with one of three access patterns to consume the secret without ever exposing the raw value in a return type.

---

## 2. Installation

```sh
# main library
pnpm add vaultkeeper

# test utilities (dev dependency)
pnpm add -D @vaultkeeper/test-helpers
```

For npm or yarn projects substitute `npm install` or `yarn add` accordingly.

---

## 3. Core Workflow

### Step 1 — Initialize

```ts
import { VaultKeeper } from 'vaultkeeper'

// Default: loads config from the platform-appropriate directory,
// runs doctor preflight checks automatically.
const vault = await VaultKeeper.init()

// Skip doctor (useful in CI or if you know the system is ready):
const vault = await VaultKeeper.init({ skipDoctor: true })

// Provide config directly instead of loading from disk:
const vault = await VaultKeeper.init({ config: myConfig })

// Override the config directory:
const vault = await VaultKeeper.init({ configDir: '/custom/path' })
```

`VaultKeeper.init()` is the only way to construct an instance; the constructor is private. It runs doctor checks unless `skipDoctor: true` is passed, loads or accepts config, initialises the `KeyManager`, and resolves the first enabled backend.

### Step 2 — Setup (store → JWE)

The backend must already contain the secret before `setup()` is called. `setup()` reads from the backend; it does not write to it.

```ts
// Produce a compact JWE string. Store this string; it is your access token.
const jwe = await vault.setup('my-api-key')

// With options:
const jwe = await vault.setup('my-api-key', {
  ttlMinutes: 30,          // default comes from config
  useLimit: 1,             // null = unlimited (default)
  executablePath: '/usr/local/bin/myapp',  // enables TOFU identity binding
  trustTier: 2,            // 1 | 2 | 3, default comes from config
  backendType: 'keychain', // override the backend used
})
```

The returned JWE is an opaque compact string (five dot-separated Base64URL segments). Store it wherever it is convenient — a file, environment variable, or database row. It is safe to store because the secret is encrypted inside it.

### Step 3 — Authorize (JWE → CapabilityToken)

```ts
const { token, response } = await vault.authorize(jwe)

// Always check for rotatedJwt and persist it if present:
if (response.rotatedJwt !== undefined) {
  // Overwrite the stored JWE with the re-encrypted version.
  // If you do not do this, the JWE will eventually fail decryption
  // once the grace period expires.
  persistJwe(response.rotatedJwt)
}
```

`authorize()` validates expiry, the blocklist, usage count limits, and (when configured) the caller's executable identity against the TOFU manifest. On success it returns an opaque `CapabilityToken` and a `VaultResponse`.

### Step 4 — Access (one of three patterns)

Use the `CapabilityToken` with one of the access methods described in section 5. The raw secret never appears in any method's return value.

---

## 4. Configuration

### VaultConfig structure

```ts
interface VaultConfig {
  version: number          // must be 1
  backends: BackendConfig[]  // ordered; the first enabled backend wins
  keyRotation: {
    gracePeriodDays: number  // how long the previous key decrypts after rotation
  }
  defaults: {
    ttlMinutes: number       // default JWE TTL
    trustTier: TrustTier     // 1 | 2 | 3
  }
  developmentMode?: {
    executables: string[]    // paths that bypass TOFU in dev
  }
}

interface BackendConfig {
  type: string      // e.g. 'keychain', 'file', '1password'
  enabled: boolean
  plugin?: boolean  // true for 1password and yubikey
  path?: string     // for file backend
}
```

### Default config (when no config file exists)

```json
{
  "version": 1,
  "backends": [{ "type": "file", "enabled": true }],
  "keyRotation": { "gracePeriodDays": 7 },
  "defaults": { "ttlMinutes": 60, "trustTier": 3 }
}
```

### Config file location

`VaultKeeper.init()` looks for `config.json` inside the platform-appropriate directory:

| Platform | Path |
|----------|------|
| macOS / Linux | `~/.config/vaultkeeper/config.json` |
| Windows | `%APPDATA%\vaultkeeper\config.json` (falls back to `~/AppData/Roaming/vaultkeeper/config.json`) |

Override the directory with `VaultKeeperOptions.configDir` or by passing a `VaultConfig` object directly via `VaultKeeperOptions.config`.

---

## 5. Access Patterns

There are three access patterns. Choose based on what the secret is used for.

### 5a. Delegated Fetch

Use when the secret must be sent in an HTTP request (API key in header, bearer token, URL parameter). The raw secret never appears in the return value — only the `Response` object from `fetch()` is returned.

```ts
const { response, vaultResponse } = await vault.fetch(token, {
  url: 'https://api.example.com/data',
  method: 'GET',
  headers: {
    Authorization: 'Bearer {{secret}}',
    'X-Custom-Header': 'prefix-{{secret}}-suffix',
  },
})
```

The `{{secret}}` placeholder is replaced in:
- `url` — for API-key-in-URL patterns
- any `headers` value
- `body` — for POST bodies

The `FetchRequest` interface:
```ts
interface FetchRequest {
  url: string
  method?: string
  headers?: Record<string, string>
  body?: string
}
```

The return type:
```ts
{ response: Response; vaultResponse: VaultResponse }
```

### 5b. Delegated Exec

Use when the secret must be passed to a subprocess — for example, authenticating a CLI tool. Never put the secret in `args` as a plain string value; use `{{secret}}` so vaultkeeper injects it after you cannot accidentally log it.

The secret is injected into:
- any element of `args` that contains `{{secret}}`
- any value in the `env` map that contains `{{secret}}`

The secret is NEVER injected into `command` itself. Do not use it there.

```ts
const { result, vaultResponse } = await vault.exec(token, {
  command: 'aws',
  args: ['s3', 'ls'],
  env: {
    AWS_SESSION_TOKEN: '{{secret}}',
  },
  cwd: '/workspace',
})

console.log(result.stdout)
console.log(result.exitCode)
```

The `ExecRequest` interface:
```ts
interface ExecRequest {
  command: string
  args?: string[]
  env?: Record<string, string>
  cwd?: string
}
```

The `ExecResult` interface:
```ts
interface ExecResult {
  stdout: string
  stderr: string
  exitCode: number
}
```

### 5c. Controlled Direct (SecretAccessor)

Use when the secret must be read directly — for example, to compute a hash, derive a key, or pass to a library that does not accept placeholders. This is the highest-risk access pattern; only use it when delegated fetch/exec cannot satisfy the use case.

```ts
const accessor = vault.getSecret(token)

accessor.read((buf) => {
  // buf is a Buffer containing the UTF-8 encoded secret.
  // Use it here. Do NOT store buf or return it from this callback.
  const derived = crypto.createHmac('sha256', buf).update(payload).digest('hex')
  // buf is zeroed automatically when this callback returns.
})

// accessor is now consumed. Calling accessor.read() again throws:
// "SecretAccessor has already been consumed — call getSecret() again"
```

The `SecretAccessor` interface:
```ts
interface SecretAccessor {
  read(callback: (buf: Buffer) => void): void
}
```

Key properties of `SecretAccessor`:
- **Single-use.** The second call to `read()` throws. If you need to read the secret again, call `vault.getSecret(token)` again (which requires another `authorize()` call if the token has a `useLimit` of 1).
- **Auto-zeroing.** The `Buffer` passed to the callback is filled with zeros in the `finally` block immediately after the callback returns, even if the callback throws.
- **Revocable proxy.** After the first `read()` completes, the proxy is revoked. Any subsequent property access on the accessor object throws a `TypeError`.
- **Inspect-safe.** `util.inspect(accessor)` returns `'[SecretAccessor]'`; the secret is never printed.

---

## 6. Backend Types

Six backends are available. vaultkeeper uses the first enabled backend in the `backends` array.

| Type | Platform | Plugin | Storage |
|------|----------|--------|---------|
| `keychain` | macOS only | No | macOS Keychain via `security` CLI |
| `dpapi` | Windows only | No | Windows DPAPI via PowerShell; blobs stored in `~/.vaultkeeper/dpapi/` |
| `secret-tool` | Linux only | No | GNOME Keyring / libsecret via `secret-tool` CLI |
| `file` | All | No | AES-256-GCM encrypted file; default path `~/.config/vaultkeeper/secrets/` |
| `1password` | All | Yes | 1Password via `op` CLI |
| `yubikey` | All | Yes | YubiKey PIV via `ykman` CLI |

Plugin backends (`1password`, `yubikey`) require an external binary and are flagged with `plugin: true` in `BackendConfig`. If the binary is not installed, `store()` and `retrieve()` throw `PluginNotFoundError` with a `.plugin` field (the binary name) and an `.installUrl` field.

**Recommend platform-native backends first.** Use `keychain` on macOS, `dpapi` on Windows, `secret-tool` on Linux. Fall back to `file` only when no native backend is appropriate. The `1password` and `yubikey` backends are suitable for teams that already use those tools.

### Using BackendRegistry

`BackendRegistry` allows registering custom backends at runtime. It is primarily used by `TestVault.create()` to register `InMemoryBackend`, but you can also use it to plug in your own implementation:

```ts
import { BackendRegistry } from 'vaultkeeper'

BackendRegistry.register('my-custom-backend', () => new MyBackend())
```

`BackendRegistry.create(type)` is called internally by `VaultKeeper.init()` to instantiate the first enabled backend.

---

## 7. Key Rotation

### Rotating a key

```ts
await vault.rotateKey()
```

After rotation:
- A new current key is generated.
- The previous key remains valid for decryption during the grace period (`keyRotation.gracePeriodDays` from config).
- JWEs presented during the grace period decrypt successfully and `authorize()` returns `response.keyStatus === 'previous'` along with a `rotatedJwt` field containing the same claims re-encrypted under the new key.
- After the grace period, the previous key is automatically discarded. JWEs encrypted with the old key will then throw `KeyRotatedError` on `authorize()`.

`rotateKey()` throws `RotationInProgressError` if a previous rotation is still within its grace period (i.e. you cannot stack rotations).

### Revoking a key (emergency)

```ts
await vault.revokeKey()
```

Emergency revocation immediately discards the previous key and generates a new current key. Any in-flight grace period is cancelled. JWEs encrypted with the revoked key become permanently unreadable — they will throw `KeyRevokedError` on any subsequent `authorize()` call. Call `setup()` again to produce a fresh JWE with the new key.

### Handling rotatedJwt

Always check for `rotatedJwt` after every `authorize()` call and persist it if present:

```ts
const { token, response } = await vault.authorize(storedJwe)
if (response.rotatedJwt !== undefined) {
  // Replace the persisted JWE with the re-encrypted version.
  // The old JWE will fail once the grace period expires.
  await saveJwe(response.rotatedJwt)
}
```

Failing to persist `rotatedJwt` means the stored JWE will eventually be unreadable once the grace period elapses and the previous key is retired.

---

## 8. Identity and Trust

### Trust tiers

`TrustTier` is `1 | 2 | 3`. Higher numbers mean stricter verification.

| Tier | Meaning |
|------|---------|
| 1 | SHA-256 hash of the executable binary — basic TOFU (trust-on-first-use) |
| 2 | SHA-256 hash + sigstore / code-signing verification (when available) |
| 3 | Full sigstore verification required; setup fails if sigstore is unavailable |

The tier is embedded in the JWE claims (`tid` field) and enforced when `setup()` computes the executable identity. Specify it in config `defaults.trustTier` or override per-call with `SetupOptions.trustTier`.

### TOFU (trust-on-first-use)

When `executablePath` is provided to `setup()` (and it is not `'dev'`, and not in the development-mode list), vaultkeeper:

1. Computes the SHA-256 hash of the executable at `executablePath`.
2. Looks up the hash in the on-disk trust manifest (`~/.config/vaultkeeper/manifest.json` by default).
3. If the executable has not been seen before, its hash is recorded (first use).
4. If the executable has been seen before but the hash has changed, `setup()` throws `IdentityMismatchError` with `.previousHash` and `.currentHash`. The caller must re-approve the executable before a new token can be issued.

### Development mode

Development mode relaxes identity verification for listed executables. When `executablePath` matches an entry in `config.developmentMode.executables`, or when `executablePath` is the string `'dev'`, TOFU is skipped and the `exe` claim is set to `'dev'`.

Enable dev mode for an executable at runtime:

```ts
await vault.setDevelopmentMode('/absolute/path/to/dev-server', true)
await vault.setDevelopmentMode('/absolute/path/to/dev-server', false) // remove
```

Development mode should never be used in production. It exists for local workflows where binaries are rebuilt frequently.

---

## 9. Error Handling

All errors extend `VaultError`. Catch `VaultError` to handle any library error; catch specific subclasses for structured recovery.

### Error hierarchy

```
VaultError
├── BackendLockedError        (.interactive: boolean)
├── DeviceNotPresentError     (.timeoutMs: number)
├── AuthorizationDeniedError
├── BackendUnavailableError   (.reason: string, .attempted: string[])
├── PluginNotFoundError       (.plugin: string, .installUrl: string)
├── SecretNotFoundError
├── TokenExpiredError         (.canRefresh: boolean)
├── KeyRotatedError
├── KeyRevokedError
├── TokenRevokedError
├── UsageLimitExceededError
├── IdentityMismatchError     (.previousHash: string, .currentHash: string)
├── SetupError                (.dependency: string)
├── FilesystemError           (.path: string, .permission: string)
└── RotationInProgressError
```

### Error class reference

| Class | When thrown | Key typed fields |
|-------|-------------|-----------------|
| `VaultError` | Base class — never thrown directly (except one case during init when system not ready) | — |
| `BackendLockedError` | Keychain / DPAPI requires user interaction before access | `interactive: boolean` — when `true`, prompting the user and retrying may succeed |
| `DeviceNotPresentError` | YubiKey or smart card is not plugged in | `timeoutMs: number` — how long the operation waited |
| `AuthorizationDeniedError` | User cancelled an OS permission dialog | — |
| `BackendUnavailableError` | No enabled backend is configured, or all attempted backends failed | `reason: string` (e.g. `'none-enabled'`, `'all-failed'`, `'unknown-type'`); `attempted: string[]` |
| `PluginNotFoundError` | `op` or `ykman` binary not installed | `plugin: string` (binary name); `installUrl: string` |
| `SecretNotFoundError` | The requested secret does not exist in the backend | — |
| `TokenExpiredError` | JWE `exp` claim has passed | `canRefresh: boolean` — when `true`, the secret still exists and `setup()` can issue a new token |
| `KeyRotatedError` | JWE was encrypted with a key that has passed its grace period | — |
| `KeyRevokedError` | JWE was encrypted with a key that was explicitly revoked | — |
| `TokenRevokedError` | JWE has been blocklisted (e.g. after a single-use token was consumed) | — |
| `UsageLimitExceededError` | Token presented more times than its `use` limit allows | — |
| `IdentityMismatchError` | Executable hash changed since it was first approved (TOFU conflict) | `previousHash: string`; `currentHash: string` |
| `SetupError` | Required system dependency missing or incompatible during init | `dependency: string` (dependency name) |
| `FilesystemError` | Config directory or secret file not accessible | `path: string`; `permission: string` (e.g. `'read'`, `'write'`) |
| `RotationInProgressError` | `rotateKey()` called while a grace period is still active | — |

### Recommended error handling pattern

```ts
import {
  VaultError,
  TokenExpiredError,
  KeyRotatedError,
  KeyRevokedError,
  IdentityMismatchError,
  BackendLockedError,
  PluginNotFoundError,
} from 'vaultkeeper'

try {
  const { token, response } = await vault.authorize(jwe)
  if (response.rotatedJwt !== undefined) {
    await persistJwe(response.rotatedJwt)
  }
  // ... use token
} catch (err) {
  if (err instanceof TokenExpiredError) {
    if (err.canRefresh) {
      const newJwe = await vault.setup(secretName)
      await persistJwe(newJwe)
    } else {
      // Secret no longer in backend; re-provision required
    }
  } else if (err instanceof KeyRotatedError || err instanceof KeyRevokedError) {
    // Must re-run setup() to produce a new JWE
    const newJwe = await vault.setup(secretName)
    await persistJwe(newJwe)
  } else if (err instanceof IdentityMismatchError) {
    console.error('Executable changed — re-approval required')
    console.error(`Previous hash: ${err.previousHash}`)
    console.error(`Current hash:  ${err.currentHash}`)
  } else if (err instanceof BackendLockedError) {
    if (err.interactive) {
      // Prompt the user to unlock and retry
    }
  } else if (err instanceof PluginNotFoundError) {
    console.error(`Install ${err.plugin}: ${err.installUrl}`)
  } else if (err instanceof VaultError) {
    // Catch-all for any other library error
    console.error(err.message)
  } else {
    throw err  // Re-throw non-library errors
  }
}
```

---

## 10. Testing

### TestVault (recommended)

`TestVault` wraps a real `VaultKeeper` instance backed by `InMemoryBackend`. It skips doctor checks and uses dev-mode identity. Use it in all unit, integration, and end-to-end tests that exercise vaultkeeper code.

```ts
import { TestVault } from '@vaultkeeper/test-helpers'

// Create a fresh vault (async):
const vault = await TestVault.create()

// vault.keeper is the VaultKeeper instance
// vault.backend is the InMemoryBackend

// Pre-populate the backend before calling setup():
await vault.backend.store('db-password', 'hunter2')

// Now use the keeper normally:
const jwe = await vault.keeper.setup('db-password')
const { token, response } = await vault.keeper.authorize(jwe)

// Reset between tests:
vault.reset()  // clears all stored secrets; same as vault.backend.clear()
```

With options:
```ts
const vault = await TestVault.create({
  ttlMinutes: 1,   // short TTL for expiry tests
  trustTier: 2,
})
```

### InMemoryBackend (standalone)

Use `InMemoryBackend` directly when you need to register a custom backend with `BackendRegistry` or test a component that depends on `SecretBackend` without using the full `TestVault` wrapper.

```ts
import { InMemoryBackend } from '@vaultkeeper/test-helpers'
import { BackendRegistry } from 'vaultkeeper'

const backend = new InMemoryBackend()
BackendRegistry.register('memory', () => backend)

await backend.store('api-key', 'test-value')
console.log(backend.size)  // 1
await backend.clear()      // remove all entries
```

`InMemoryBackend` is always available (`isAvailable()` returns `true`). Its `type` is `'memory'` and `displayName` is `'In-Memory Backend'`.

### Test pattern

```ts
import { describe, it, beforeEach, expect } from 'vitest'
import { TestVault } from '@vaultkeeper/test-helpers'
import { TokenExpiredError } from 'vaultkeeper'

describe('my vault consumer', () => {
  let vault: TestVault

  beforeEach(async () => {
    vault = await TestVault.create()
  })

  afterEach(() => {
    vault.reset()
  })

  it('should authorize and fetch with secret', async () => {
    await vault.backend.store('api-key', 'test-secret-value')
    const jwe = await vault.keeper.setup('api-key')
    const { token } = await vault.keeper.authorize(jwe)
    // ... assert on vault.keeper.fetch(token, ...) or vault.keeper.getSecret(token)
  })

  it('should throw TokenExpiredError on expired token', async () => {
    const shortVault = await TestVault.create({ ttlMinutes: 0.001 })  // ~60ms
    await shortVault.backend.store('api-key', 'value')
    const jwe = await shortVault.keeper.setup('api-key')
    await new Promise(resolve => setTimeout(resolve, 100))  // let it expire
    await expect(shortVault.keeper.authorize(jwe)).rejects.toBeInstanceOf(TokenExpiredError)
  })
})
```

---

## 11. Doctor / Preflight Checks

### Running the doctor

```ts
// Run as a static method without initializing a full vault:
const result = await VaultKeeper.doctor()
```

`VaultKeeper.init()` runs the doctor automatically unless `skipDoctor: true` is passed. If `result.ready` is `false`, `init()` throws a `VaultError` with a message listing the required steps.

### PreflightResult structure

```ts
interface PreflightResult {
  checks: PreflightCheck[]  // one per dependency inspected
  ready: boolean            // true when all required checks pass
  warnings: string[]        // non-fatal, optional dependencies missing
  nextSteps: string[]       // action items for failed required checks
}

interface PreflightCheck {
  name: string
  status: 'ok' | 'missing' | 'version-unsupported'
  version?: string    // detected version, when found
  reason?: string     // human-readable explanation when status is not 'ok'
}
```

---

## 12. Security Rules to Enforce in Generated Code

When generating code that uses vaultkeeper, enforce the following rules. Do not suggest patterns that violate them.

### Never pass secrets as CLI arguments

`delegatedExec` uses `spawn()` with an argument array. While the secret is injected into `args` elements at the last moment before spawning, this means the secret appears in the process argument list visible to other processes via `/proc` or `ps`. When possible, inject the secret via `env` instead of `args`.

```ts
// Prefer: inject via environment variable
vault.exec(token, {
  command: 'my-tool',
  env: { MY_TOOL_SECRET: '{{secret}}' },
})

// Acceptable but higher risk: inject via arg (still supported by the API)
vault.exec(token, {
  command: 'my-tool',
  args: ['--password', '{{secret}}'],
})
```

Never construct a command string with the secret concatenated as a plain value and then split it into args. Always use the `{{secret}}` placeholder.

### Never store a reference to the Buffer outside the SecretAccessor callback

```ts
// WRONG — storing a reference means the secret outlives the zeroing:
let leaked: Buffer
accessor.read((buf) => {
  leaked = buf  // DO NOT DO THIS
})
// leaked now contains zeroed bytes and is a security footprint

// CORRECT — use the secret only inside the callback:
accessor.read((buf) => {
  const result = myLib.derive(buf)
  storeResult(result)
})
```

### Never return the raw secret string from any function

`VaultKeeper` methods are designed so the secret never appears in a return type. Do not circumvent this by converting `buf` to a string and returning it:

```ts
// WRONG:
function getApiKey(accessor: SecretAccessor): string {
  let key = ''
  accessor.read((buf) => { key = buf.toString('utf8') })
  return key  // raw secret is now a long-lived string
}

// CORRECT: compute what you need inside the callback
function signRequest(accessor: SecretAccessor, payload: string): string {
  let signature = ''
  accessor.read((buf) => {
    signature = crypto.createHmac('sha256', buf).update(payload).digest('hex')
  })
  return signature  // derived value only, not the secret
}
```

### Use AES-256-GCM for any custom symmetric encryption

vaultkeeper itself uses AES-256-GCM for JWE payloads (via the `jose` library). If you need to encrypt data in adjacent code, always use AES-256-GCM. Never use AES-CBC, which is vulnerable to padding oracle attacks and lacks authenticity.

### Zero Buffer instances after use

When you receive a `Buffer` from the `SecretAccessor` callback, do not copy it to other Buffers that are not automatically zeroed. If you must copy, zero the copy immediately after use:

```ts
accessor.read((buf) => {
  const copy = Buffer.from(buf)
  try {
    doSomethingWith(copy)
  } finally {
    copy.fill(0)
  }
})
```

### Do not construct JWE claims manually

Use `vault.setup()` to create JWE tokens. Do not attempt to construct JWE tokens manually — the `val` field must come from the backend's `retrieve()` call to ensure it is the stored secret and not an arbitrary value.

---

## 13. Common Gotchas

### The backend must be pre-populated before calling setup()

`setup()` calls `backend.retrieve(secretName)`. If the secret does not exist in the backend, it throws `SecretNotFoundError`. You are responsible for populating the backend separately (e.g. via `backend.store()`, the OS credential manager UI, or a provisioning script).

```ts
// In tests: pre-populate before setup()
await vault.backend.store('api-key', 'actual-value')
const jwe = await vault.keeper.setup('api-key')

// In production: the secret must already be in the OS keychain before setup()
// vaultkeeper does not provide a CLI to add secrets; that is the operator's job.
```

### SecretAccessor is single-use

`accessor.read()` can only be called once. The second call throws:

```
Error: SecretAccessor has already been consumed — call getSecret() again to obtain a new accessor
```

To read the secret multiple times in a single flow, either:
- Do all work inside a single `read()` callback, or
- Call `vault.getSecret(token)` again (which works for tokens with `useLimit: null` or a limit greater than the number of accesses consumed so far).

### The blocklist is in-memory only

When a use-limited token is exhausted, its JTI is added internally to a module-level `Set`. This blocklist is not persisted to disk and is not shared across processes. If you restart the process, blocked JTIs are forgotten. For production use cases that require a durable revocation list, store revoked JTIs in a database and check them before calling `authorize()`.

### RotationInProgressError when stacking rotations

You cannot rotate the key while a previous rotation is still within its grace period. Wait for the grace period to expire (or call `revokeKey()` for emergency revocation) before calling `rotateKey()` again.

### VaultKeeper.init() runs the doctor by default

In production the doctor check is appropriate. In tests and CI where you know the system is ready, always pass `skipDoctor: true` (or use `TestVault`, which does this automatically). Otherwise the doctor may fail in a headless environment that lacks optional tools.

### BackendRegistry is a global singleton

`BackendRegistry` maintains a static map. If you call `BackendRegistry.register('memory', ...)` in one test and then instantiate `VaultKeeper` in a later test in the same process, the registration persists. `TestVault.create()` re-registers the in-memory backend on every call, which is safe because it overwrites the factory. Be aware of this if you mix test suites that register different factories for the same type.

### executablePath defaults to 'dev' in setup()

When `executablePath` is omitted from `SetupOptions`, vaultkeeper uses `'dev'` as the executable identity. This means TOFU is bypassed and the `exe` claim in the JWE is the string `'dev'`. This is intentional for development but should not be relied upon in production: provide the real path to the executable that will call `authorize()` so that identity binding is enforced.

---

## Quick Reference

```ts
// Initialize
const vault = await VaultKeeper.init({ skipDoctor: true, config })

// Setup (backend must have the secret already)
const jwe = await vault.setup('secret-name', { ttlMinutes: 60, useLimit: null })

// Authorize
const { token, response } = await vault.authorize(jwe)
if (response.rotatedJwt) await persist(response.rotatedJwt)

// Access: delegated fetch
const { response } = await vault.fetch(token, {
  url: 'https://api.example.com',
  headers: { Authorization: 'Bearer {{secret}}' },
})

// Access: delegated exec
const { result } = await vault.exec(token, {
  command: 'aws',
  env: { AWS_SECRET_ACCESS_KEY: '{{secret}}' },
})

// Access: controlled direct
vault.getSecret(token).read((buf) => {
  // use buf here; it is zeroed after this returns
})

// Key rotation
await vault.rotateKey()
await vault.revokeKey()  // emergency only

// Doctor
const preflight = await VaultKeeper.doctor()

// Tests
const vault = await TestVault.create()
await vault.backend.store('my-secret', 'value')
vault.reset()  // clear between tests
```
