# vaultkeeper

Unified, policy-enforced secret storage across OS backends. Secrets are stored in the native credential store for the current platform and accessed through short-lived JWE tokens. No secret ever appears in a return value — callers use delegated patterns that inject the value at the last possible moment.

## Requirements

- Node >= 20

## Installation

```sh
pnpm add vaultkeeper
```

## Quick start

```ts
import { VaultKeeper } from 'vaultkeeper'

// 1. Initialize (runs doctor preflight checks)
const vault = await VaultKeeper.init()

// 2. Store a secret and mint a JWE token
//    The secret must already exist in the backend (e.g. macOS Keychain).
const jwe = await vault.setup('MY_API_KEY')

// 3. Authorize: decrypt and validate the token
const { token, response } = await vault.authorize(jwe)

// 4a. Delegated fetch — secret injected into the request, never returned
const { response: httpResponse } = await vault.fetch(token, {
  url: 'https://api.example.com/data',
  headers: { Authorization: 'Bearer {{secret}}' },
})

// 4b. Delegated exec — secret injected via env var, never on the command line
//     Avoid putting secrets in `args` — process arguments are visible via `ps`.
const { result } = await vault.exec(token, {
  command: 'my-api-client',
  args: ['--use-env-token'],
  env: { MY_API_TOKEN: '{{secret}}' },
})

// 4c. Controlled direct access — buffer is zeroed after the callback returns
const accessor = vault.getSecret(token)
accessor.read((buf) => {
  // Use buf here. Do not store a reference beyond this callback.
  doSomethingWith(buf.toString('utf8'))
})
```

## Backends

The first enabled backend in the configuration is used.

| Type | Platform | Notes |
|------|----------|-------|
| `keychain` | macOS | macOS Keychain (built-in) |
| `dpapi` | Windows | Windows DPAPI (built-in) |
| `secret-tool` | Linux | `libsecret` / `secret-tool` (built-in) |
| `file` | All | AES-256-GCM encrypted file fallback (built-in) |
| `1password` | All | 1Password `op` CLI (plugin) |
| `yubikey` | All | YubiKey `ykman` (plugin) |

## Access patterns

### Delegated fetch

The secret is substituted for every `{{secret}}` placeholder in `url`, `headers`, and `body` before the request is sent. The raw secret value is never returned.

```ts
const { response } = await vault.fetch(token, {
  url: 'https://api.example.com/endpoint',
  method: 'POST',
  headers: { Authorization: 'Bearer {{secret}}' },
  body: JSON.stringify({ key: '{{secret}}' }),
})
```

### Delegated exec

The secret is substituted for every `{{secret}}` placeholder in `env` values before the process is spawned. Do **not** pass secrets in CLI arguments — process arguments may be visible to other users via `ps` or collected in logs and telemetry.

```ts
const { result } = await vault.exec(token, {
  command: 'my-tool',
  args: ['run', '--config', '/etc/my-tool/config.yaml'],
  env: { API_KEY: '{{secret}}' },
  cwd: '/tmp',
})
console.log(result.stdout, result.exitCode)
```

### Controlled direct access

A single-use accessor wraps the secret in a `Buffer`. The buffer is zeroed immediately after the callback returns. Calling `read()` a second time throws.

```ts
const accessor = vault.getSecret(token)
accessor.read((buf) => {
  // buf is a temporary Buffer — do not store it
  sendToSdk(buf.toString('utf8'))
})
```

## Doctor / preflight

`VaultKeeper.init()` runs preflight checks automatically. To run checks without initializing:

```ts
import { VaultKeeper, runDoctor } from 'vaultkeeper'

// Via the class
const result = await VaultKeeper.doctor()

// Or standalone
const result = await runDoctor()

console.log(result.ready)      // boolean
console.log(result.checks)     // PreflightCheck[]
console.log(result.warnings)   // string[]
console.log(result.nextSteps)  // string[]
```

Pass `skipDoctor: true` to bypass preflight on init:

```ts
const vault = await VaultKeeper.init({ skipDoctor: true })
```

## Key rotation

Keys are AES-256-GCM. After rotation the previous key remains valid for decryption for the duration of the configured grace period. JWEs presented during the grace period include a `rotatedJwt` in the `VaultResponse` — persist the new token to avoid breakage after the grace period expires.

```ts
// Rotate — previous key stays valid for gracePeriodDays
await vault.rotateKey()

// After authorize(), check whether to persist a new token
const { token, response } = await vault.authorize(jwe)
if (response.rotatedJwt !== undefined) {
  await persistToken(response.rotatedJwt)
}

// Emergency revocation — previous key invalidated immediately
await vault.revokeKey()
```

## Trust tiers

Executable identity is verified during `setup()`. A `trustTier` value can be attached to the resulting token as a policy label.

> **Note:** In the current implementation, `trustTier` is recorded in the token claims but does not change which verification mechanism is used. Future versions may introduce tier-specific verification behavior.

| Tier | Intended method |
|------|-----------------|
| `1` | Sigstore transparency log |
| `2` | Registry signature |
| `3` | TOFU (Trust On First Use) — hash stored in trust manifest |

Pass `trustTier` in setup options to override the configured default:

```ts
const jwe = await vault.setup('MY_API_KEY', {
  executablePath: '/usr/local/bin/my-tool',
  trustTier: 3,
})
```

## Development mode

Development mode bypasses TOFU identity verification for listed executables — useful for local workflows where the binary changes frequently.

```ts
await vault.setDevelopmentMode('/path/to/my-dev-tool', true)

// Or set executablePath to 'dev' directly in setup:
const jwe = await vault.setup('MY_API_KEY', { executablePath: 'dev' })
```

## Configuration

Config is loaded from `~/.config/vaultkeeper/config.json` by default. Override with `configDir` in init options or supply `config` directly.

```json
{
  "version": 1,
  "backends": [
    { "type": "keychain", "enabled": true },
    { "type": "file", "enabled": false, "path": "~/.config/vaultkeeper/secrets.enc" }
  ],
  "keyRotation": {
    "gracePeriodDays": 7
  },
  "defaults": {
    "ttlMinutes": 60,
    "trustTier": 3
  },
  "developmentMode": {
    "executables": ["/usr/local/bin/my-dev-tool"]
  }
}
```

## Setup options

```ts
const jwe = await vault.setup('SECRET_NAME', {
  ttlMinutes: 30,          // token TTL (default: from config)
  useLimit: 1,             // null for unlimited
  executablePath: '/path/to/caller', // or 'dev' to skip identity check
  trustTier: 3,
  backendType: 'keychain',
})
```

## Error types

All errors extend `VaultError`.

| Class | When thrown |
|-------|-------------|
| `BackendLockedError` | Keychain or credential store is locked |
| `DeviceNotPresentError` | Required hardware device not connected |
| `AuthorizationDeniedError` | User denied an OS permission dialog |
| `BackendUnavailableError` | No configured backend is reachable |
| `PluginNotFoundError` | A required plugin binary is not installed |
| `SecretNotFoundError` | Secret does not exist in the backend |
| `TokenExpiredError` | JWE has passed its `exp` claim |
| `KeyRotatedError` | Key exited grace period; JWE is permanently unreadable |
| `KeyRevokedError` | Key was explicitly revoked |
| `TokenRevokedError` | Token has been blocked (e.g. single-use token already consumed) |
| `UsageLimitExceededError` | Token presented more times than its `use` limit allows |
| `IdentityMismatchError` | Executable hash changed since TOFU approval |
| `SetupError` | Required system dependency missing or incompatible at init |
| `FilesystemError` | Config directory not readable or writable |
| `RotationInProgressError` | `rotateKey()` called while previous key is still in grace period |

## License

ISC
