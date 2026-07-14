# vaultkeeper

Unified, policy-enforced secret storage across OS backends. Secrets are stored in the native credential store for the current platform and accessed through short-lived JWE tokens. No secret ever appears in a return value — callers use delegated patterns that inject the value at the last possible moment.

Available as a **native Rust CLI**, a **TypeScript library**, a **WASM-backed SDK**, and a **Node.js CLI**.

## Which package should I use?

- **`vaultkeeper`** — the pure TypeScript library. Use this by default: it offers the delegated access patterns (`fetch`, `exec`, `createSecretAccessor`) that keep raw secrets out of application memory. With no config file present it falls back to the file backend, same as the WASM SDK; run `vaultkeeper config init` to write the platform-default backend instead (Keychain on macOS, DPAPI on Windows, `file` on Linux).
- **`@vaultkeeper/wasm`** — a WASM-backed SDK with a similar feature set, backed by the Rust core instead of the `jose` npm package. Reach for it when you specifically need the Rust implementation (e.g. to match native-CLI behavior exactly) or want to avoid a `jose` dependency. It hardcodes the file backend rather than using platform defaults — see [WASM SDK quick start](#wasm-sdk-quick-start).
- **`@vaultkeeper/cli`** — the Node.js CLI (`vaultkeeper` on the command line). Use this for shell scripts, CI pipelines, or interactive use where you don't need a library API at all.

## Installation

### Native CLI (Rust)

Build from source using Cargo:

```sh
cargo install vaultkeeper-cli
```

This installs the `vaultkeeper` binary into `~/.cargo/bin/`.

**Requirements:** Rust toolchain (rustup)

### Node.js CLI

```sh
pnpm add -g @vaultkeeper/cli
# or
npm install -g @vaultkeeper/cli
```

Then run:

```sh
vaultkeeper --help
```

**Requirements:** Node >= 20

### TypeScript library

```sh
pnpm add vaultkeeper
```

`vaultkeeper`'s public API references Node's `Buffer` type (e.g. `SecretAccessor.read()`, `SignRequest`, `VerifyRequest`). Install `@types/node` as a devDependency so your project typechecks against it — it's declared as an optional peer dependency, but npm/pnpm/yarn do not install optional peers automatically, so you need to add it yourself:

```sh
pnpm add -D @types/node
```

### WASM SDK

The WASM SDK wraps the Rust core compiled to WebAssembly. It offers a similar high-level feature set to the TypeScript library, but the public API is not a drop-in replacement — some function signatures differ (e.g., `setup(secretName, secretValue, ...)` vs the TS library's `setup(secretName, options?)`).

```sh
pnpm add @vaultkeeper/wasm
```

**Requirements:** Node >= 20.13.0

## CLI usage

Both the native Rust CLI and the Node.js CLI share the same command surface:

```sh
# Run preflight checks
vaultkeeper doctor

# Initialize configuration
vaultkeeper config init

# Show current configuration
vaultkeeper config show

# Store a secret (reads from stdin)
echo "my-secret-value" | vaultkeeper store --name MY_API_KEY

# Delete a secret
vaultkeeper delete --name MY_API_KEY

# Pre-approve an executable (TOFU): records its SHA-256 in the trust manifest
vaultkeeper approve --script /usr/local/bin/my-tool

# Enable (or disable) development mode for a script
vaultkeeper dev-mode enable --script /path/to/script

# Run a command with a secret injected into an env var (approve the caller first,
# above; see "Running in CI" below for the non-interactive form)
vaultkeeper exec --secret MY_API_KEY --env MY_API_KEY --caller /usr/local/bin/my-tool -- my-command --flag

# Rotate the encryption key (previous key stays valid during grace period)
vaultkeeper rotate-key

# Emergency key revocation (previous key invalidated immediately)
vaultkeeper revoke-key
```

### Running in CI

`vaultkeeper exec` requires approval the first time a caller requests a secret.
On an interactive terminal you are prompted `[y/N]`; with non-TTY stdin (CI,
Docker) there is no prompt, so approve the caller ahead of time — or approve a
single invocation with `--yes` (or `VAULTKEEPER_YES=1`). The `file` backend needs
no system credential store, which makes it a good fit for CI.

```sh
# Recommended: pre-approve the caller once, then exec runs unattended.
vaultkeeper approve --script "$CI_SCRIPT"
echo "$MY_SECRET" | vaultkeeper store --name MY_API_KEY
vaultkeeper exec --secret MY_API_KEY --env API_KEY --caller "$CI_SCRIPT" -- ./deploy.sh

# Or approve a single run non-interactively (records the caller for next time):
vaultkeeper exec --yes --secret MY_API_KEY --env API_KEY --caller "$CI_SCRIPT" -- ./deploy.sh
# equivalently: VAULTKEEPER_YES=1 vaultkeeper exec --secret MY_API_KEY ...
```

A caller whose contents changed since approval is never silently trusted — you
must re-approve it with `vaultkeeper approve --script <caller>`.

## TypeScript quick start

> [!WARNING]
> With no config file present, a bare `VaultKeeper.init()` — and `vaultkeeper config init` with no `--backend` — targets your **real OS credential store**: the macOS Keychain on macOS, Windows DPAPI on Windows. On those platforms, secrets you store land in the live system store. To use a portable, CI-friendly encrypted file instead, choose the `file` backend explicitly (shown below). Inspect `vault.activeBackendType` to confirm which backend an instance resolved to.

```ts
import { VaultKeeper } from 'vaultkeeper'

// 1. Initialize (runs doctor preflight checks)
//    With no config file, the backend defaults to the platform's OS credential
//    store (keychain on macOS, dpapi on Windows, file elsewhere).
const vault = await VaultKeeper.init()
console.log(vault.activeBackendType) // e.g. "keychain" on macOS

// Prefer a portable, CI-friendly encrypted file? Pass an explicit config:
// const vault = await VaultKeeper.init({
//   config: {
//     version: 1,
//     backends: [{ type: 'file', enabled: true }],
//     keyRotation: { gracePeriodDays: 7 },
//     defaults: { ttlMinutes: 60, trustTier: 3 },
//   },
// })
// From the CLI, the equivalent is: vaultkeeper config init --backend file

// 2. Store a secret in the configured backend
await vault.store('MY_API_KEY', 'my-secret-value')

// 3. Mint a JWE token for the stored secret
const jwe = await vault.setup('MY_API_KEY')

// 4. Authorize: decrypt and validate the token
const { token, vaultResponse } = await vault.authorize(jwe)

// 5a. Delegated fetch — secret injected into the request, never returned
const { response: httpResponse } = await vault.fetch(token, {
  url: 'https://api.example.com/data',
  headers: { Authorization: 'Bearer {{secret}}' },
})

// 5b. Delegated exec — secret injected via env var, never on the command line
//     Avoid putting secrets in `args` — process arguments are visible via `ps`.
const { result } = await vault.exec(token, {
  command: 'my-api-client',
  args: ['--use-env-token'],
  env: { MY_API_TOKEN: '{{secret}}' },
})

// 5c. Controlled direct access — buffer is zeroed after the callback returns
const accessor = vault.getSecret(token)
accessor.read((buf) => {
  // Use buf here. Do not store a reference beyond this callback.
  doSomethingWith(buf.toString('utf8'))
})
```

## Storing secrets

Before calling `setup()`, the secret must exist in the backend. There are three ways to populate it.

**CLI:**

```sh
echo "my-secret-value" | vaultkeeper store --name MY_API_KEY
```

**TypeScript API:**

```ts
import { BackendRegistry } from 'vaultkeeper'

// Create a backend instance and store the secret
const backend = BackendRegistry.create('file')
await backend.store('MY_API_KEY', 'my-secret-value')
```

**Test helper (in-memory, no OS dependencies):**

```ts
import { TestVault } from '@vaultkeeper/test-helpers'

const { keeper, backend } = await TestVault.create()
await backend.store('MY_API_KEY', 'my-secret-value')
const jwe = await keeper.setup('MY_API_KEY')
```

## WASM SDK quick start

The WASM SDK exposes lower-level APIs than the TypeScript library's delegated patterns. Methods like `store()` and `retrieve()` handle raw secret values directly — use the delegated access patterns (fetch/exec) from the TypeScript library when you need to avoid exposing secrets in application memory.

**The WASM SDK always uses the file backend.** Unlike the native and Node.js CLIs and the TypeScript library, it does not read the `backends` config and does not use the platform-default credential store (Keychain, DPAPI, `secret-tool`) — secrets are always stored in the AES-256-GCM encrypted file backend regardless of platform.

```ts
import { createVaultKeeper } from '@vaultkeeper/wasm'

const vault = await createVaultKeeper()

// Store a secret
await vault.store('MY_API_KEY', 'my-secret-value')

// Mint a JWE token
const jwe = vault.setup('MY_API_KEY', 'my-secret-value')

// Authorize: decrypt and validate. The result's `claims` never contain the
// raw secret — read it exactly once through the one-time accessor.
const result = vault.authorize(jwe)
const apiKey = result.secret.read((value) => value)

// Rotate or revoke keys
vault.rotateKey()
vault.revokeKey()

// Clean up
vault.dispose()
```

### `VaultKeeper` methods (`@vaultkeeper/wasm`)

| Method                                     | Description                                                                                                             |
| ------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------- |
| `static create(options?, configDir?)`      | Create a new instance (also available as the `createVaultKeeper()` convenience function)                                |
| `doctor()`                                 | Run preflight checks                                                                                                    |
| `setup(secretName, secretValue, options?)` | Create a JWE token encapsulating a secret                                                                               |
| `authorize(jwe)`                           | Decrypt and validate a JWE token; returns `{ claims, response, secret }`, where `secret` is a one-time `SecretAccessor` |
| `rotateKey()`                              | Rotate the encryption key (previous key stays valid during the grace period)                                            |
| `revokeKey()`                              | Emergency key revocation — removes the previous key and generates a new current key                                     |
| `config()`                                 | Get the current configuration                                                                                           |
| `store(id, secret)`                        | Store a secret via the file backend                                                                                     |
| `retrieve(id)`                             | Retrieve a secret via the file backend                                                                                  |
| `delete(id)`                               | Delete a secret via the file backend                                                                                    |
| `dispose()`                                | Free the underlying WASM resources                                                                                      |

## Backends

The first enabled backend in the configuration is used.

| Type          | Platform | Notes                                          |
| ------------- | -------- | ---------------------------------------------- |
| `keychain`    | macOS    | macOS Keychain (built-in)                      |
| `dpapi`       | Windows  | Windows DPAPI (built-in)                       |
| `secret-tool` | Linux    | `libsecret` / `secret-tool` (built-in)         |
| `file`        | All      | AES-256-GCM encrypted file fallback (built-in) |
| `1password`   | All      | 1Password `op` CLI (plugin)                    |
| `yubikey`     | All      | YubiKey `ykman` (plugin)                       |

## Platforms

| Platform | Default backend | Required dependencies                                            |
| -------- | --------------- | ---------------------------------------------------------------- |
| macOS    | `keychain`      | `security` (built-in)                                            |
| Linux    | `file`          | None (AES-256-GCM encrypted file, no OS credential store needed) |
| Windows  | `dpapi`         | PowerShell (built-in)                                            |
| Any      | `file`          | None (AES-256-GCM encrypted file, no OS credential store needed) |

The `file` backend works on all platforms and requires no system dependencies. Use it as a fallback or in environments without a native credential store (CI, Docker, etc.).

To use the native Linux credential store instead, install `secret-tool` (`sudo apt install libsecret-tools`) and set `"type": "secret-tool"` in your config.

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

The secret is substituted for every `{{secret}}` placeholder in `env` values before the process is spawned. Secret placeholders are **not supported** in `command` or `args` — `exec()` throws `ExecError` if one appears there. Process arguments are visible to other users via `ps` and are often collected in logs and telemetry, so inject secrets via `env` instead.

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

console.log(result.ready) // boolean
console.log(result.checks) // PreflightCheck[]
console.log(result.warnings) // string[]
console.log(result.nextSteps) // string[]
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
const { token, vaultResponse } = await vault.authorize(jwe)
if (vaultResponse.rotatedJwt !== undefined) {
  await persistToken(vaultResponse.rotatedJwt)
}

// Emergency revocation — previous key invalidated immediately
await vault.revokeKey()
```

Key material is persisted across processes. When `VaultKeeper` loads its configuration from the config directory (the CLI's normal mode — no injected `config` or `backend`), the encryption keys are written there, encrypted at rest with AES-256-GCM under an owner-only (`0600`) wrapping key. This means a token minted by one CLI process stays authorizable by a later process within its validity window, and the rotation grace period is enforced across invocations: `rotate-key` run twice while the previous key is still in its grace period fails the second time with `RotationInProgressError`. Instances created with an injected `config` or `backend` keep keys in memory only, so tests and embedders stay hermetic.

## Trust tiers

Executable identity is verified during `setup()`. A `trustTier` value can be attached to the resulting token as a policy label.

> **Note:** In the current implementation, `trustTier` is recorded in the token claims but does not change which verification mechanism is used. Future versions may introduce tier-specific verification behavior.

| Tier | Intended method                                           |
| ---- | --------------------------------------------------------- |
| `1`  | Sigstore transparency log                                 |
| `2`  | Registry signature                                        |
| `3`  | TOFU (Trust On First Use) — hash stored in trust manifest |

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

## Testing

The `@vaultkeeper/test-helpers` package provides an in-memory backend and a pre-configured `TestVault` for fast, hermetic tests with zero system dependencies:

```sh
pnpm add -D @vaultkeeper/test-helpers
```

```ts
import { TestVault } from '@vaultkeeper/test-helpers'

const { keeper, backend } = await TestVault.create()
await backend.store('MY_SECRET', 'hunter2')

const jwe = await keeper.setup('MY_SECRET')
const { token } = await keeper.authorize(jwe)
const { result } = await keeper.exec(token, {
  command: 'echo',
  args: ['done'],
  env: { SECRET: '{{secret}}' },
})
```

`TestVault` uses an in-memory backend — no OS keychain, no file system, no doctor checks.

### Testing your own code

Application code that calls `VaultKeeper.init()` internally can't be swapped onto a test backend. Structure your code to accept a `VaultKeeper` instance instead — production passes the real one, tests pass the `keeper` from a `TestVault` instance (`const { keeper } = await TestVault.create()`).

**Before** — the function constructs its own `VaultKeeper`, so a test can only exercise it against a real backend:

```ts
// src/build-auth-header.ts
import { VaultKeeper } from 'vaultkeeper'

export async function buildAuthHeader(secretName: string): Promise<string> {
  const vault = await VaultKeeper.init() // always the real backend + doctor checks
  const jwe = await vault.setup(secretName)
  const { token } = await vault.authorize(jwe)
  const accessor = vault.getSecret(token)
  let header = ''
  accessor.read((buf) => {
    header = `Bearer ${buf.toString('utf8')}`
  })
  return header
}
```

**After** — the `VaultKeeper` instance is a parameter, so the caller decides which vault to use:

```ts
// src/build-auth-header.ts
import type { VaultKeeper } from 'vaultkeeper'

export async function buildAuthHeader(vault: VaultKeeper, secretName: string): Promise<string> {
  const jwe = await vault.setup(secretName)
  const { token } = await vault.authorize(jwe)
  const accessor = vault.getSecret(token)
  let header = ''
  accessor.read((buf) => {
    header = `Bearer ${buf.toString('utf8')}`
  })
  return header
}
```

Production call site is unchanged apart from passing the vault along:

```ts
import { VaultKeeper } from 'vaultkeeper'
import { buildAuthHeader } from './build-auth-header.js'

const vault = await VaultKeeper.init()
const header = await buildAuthHeader(vault, 'MY_API_KEY')
```

Test with the `keeper` from a `TestVault` instance in place of the real vault:

```ts
// test/build-auth-header.test.ts
import { describe, expect, it } from 'vitest'
import { TestVault } from '@vaultkeeper/test-helpers'
import { buildAuthHeader } from '../src/build-auth-header.js'

describe('buildAuthHeader', () => {
  it('formats the stored secret as a Bearer token', async () => {
    const { keeper, backend } = await TestVault.create()
    await backend.store('MY_API_KEY', 'test-key-123')

    const header = await buildAuthHeader(keeper, 'MY_API_KEY')

    expect(header).toBe('Bearer test-key-123')
  })
})
```

### Injecting a backend directly

For cases where `TestVault` doesn't fit — e.g. an embedder that already has a `SecretBackend` instance — pass it via `VaultKeeperOptions.backend`. This skips both the global `BackendRegistry` and hand-assembling a full `VaultConfig`:

```ts
import { VaultKeeper } from 'vaultkeeper'
import { InMemoryBackend } from '@vaultkeeper/test-helpers'

const backend = new InMemoryBackend()
const vault = await VaultKeeper.init({ backend, skipDoctor: true })

await vault.store('MY_SECRET', 'hunter2')
const jwe = await vault.setup('MY_SECRET')
```

See the `backend` option's JSDoc for how it interacts with `config`/`configDir`.

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
  ttlMinutes: 30, // token TTL (default: from config)
  useLimit: 1, // null for unlimited
  executablePath: '/path/to/caller', // or 'dev' to skip identity check
  trustTier: 3,
  backendType: 'keychain',
})
```

## Error types

All errors extend `VaultError`. The `@vaultkeeper/wasm` package exports and throws a subset of this hierarchy (see the "In `@vaultkeeper/wasm`" column) — errors tied to platform credential-store integration or executable-identity checks that don't apply to the WASM SDK's file-backend-only, lower-level surface are TS-library-only.

| Class                      | When thrown                                                                                                                                          | In `@vaultkeeper/wasm` |
| -------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- | :--------------------: |
| `BackendLockedError`       | Keychain or credential store is locked                                                                                                               |    TS-library-only     |
| `DeviceNotPresentError`    | Required hardware device not connected                                                                                                               |    TS-library-only     |
| `AuthorizationDeniedError` | User denied an OS permission dialog                                                                                                                  |    TS-library-only     |
| `BackendUnavailableError`  | No configured backend is reachable                                                                                                                   |    TS-library-only     |
| `PluginNotFoundError`      | A required plugin binary is not installed                                                                                                            |    TS-library-only     |
| `SecretNotFoundError`      | Secret does not exist in the backend                                                                                                                 |          Yes           |
| `TokenExpiredError`        | JWE has passed its `exp` claim                                                                                                                       |          Yes           |
| `KeyRotatedError`          | Key exited grace period; JWE is permanently unreadable                                                                                               |          Yes           |
| `KeyRevokedError`          | Key was explicitly revoked                                                                                                                           |          Yes           |
| `TokenRevokedError`        | Token has been blocked (e.g. single-use token already consumed)                                                                                      |          Yes           |
| `UsageLimitExceededError`  | Token presented more times than its `use` limit allows                                                                                               |          Yes           |
| `IdentityMismatchError`    | Executable hash changed since TOFU approval                                                                                                          |    TS-library-only     |
| `ExecError`                | `exec()` request was invalid (e.g. `{{secret}}` in the `command` or `args` field) or the command could not be started (not found or failed to spawn) |    TS-library-only     |
| `InvalidTokenError`        | JWE could not be decrypted or validated (e.g. structurally malformed, tampered, or failed decryption)                                                |          Yes           |
| `AccessorConsumedError`    | `SecretAccessor.read()` called after already consumed                                                                                                |          Yes           |
| `InvalidAlgorithmError`    | Signing/verifying with a disallowed algorithm (e.g. `md5`)                                                                                           |    TS-library-only     |
| `SetupError`               | Required system dependency missing or incompatible at init                                                                                           |    TS-library-only     |
| `FilesystemError`          | Config directory not readable or writable                                                                                                            |    TS-library-only     |
| `RotationInProgressError`  | `rotateKey()` called while previous key is still in grace period                                                                                     |          Yes           |

## Architecture

vaultkeeper is a polyglot monorepo with TypeScript and Rust implementations sharing the same crypto primitives and wire format:

| Component          | Package                           | Description                                                             |
| ------------------ | --------------------------------- | ----------------------------------------------------------------------- |
| Rust core          | `vaultkeeper-core` (crate)        | All business logic, crypto (JWE, AES-256-GCM), backends, key management |
| Native CLI         | `vaultkeeper-cli` (crate)         | Standalone binary using clap                                            |
| WASM bindings      | `vaultkeeper-wasm` (crate)        | wasm-bindgen wrapper over core                                          |
| TypeScript library | `vaultkeeper` (npm)               | Pure TypeScript implementation                                          |
| WASM SDK           | `@vaultkeeper/wasm` (npm)         | Node.js wrapper around the WASM binary                                  |
| Node.js CLI        | `@vaultkeeper/cli` (npm)          | CLI using the TypeScript library                                        |
| Conformance tests  | `vaultkeeper-conformance` (crate) | Data-driven tests ensuring both CLIs match                              |

JWE tokens created by the Rust core and the TypeScript library are wire-compatible — a token minted by one can be decrypted by the other.

## License

ISC
