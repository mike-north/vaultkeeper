# vaultkeeper

Unified, policy-enforced secret storage across OS credential backends. By default secrets are stored
in a portable, self-contained AES-256-GCM encrypted `file` backend — a bare `VaultKeeper.init()`
never silently writes to your real OS credential store; the platform-native store (macOS Keychain,
Windows DPAPI) is an explicit opt-in. Secrets are accessed through short-lived JWE tokens — the raw
secret never appears in a return value.

## Installation

```sh
pnpm add vaultkeeper
```

**Requirements:** Node >= 20

## Quick start

```ts
import { VaultKeeper } from 'vaultkeeper'

// 1. Initialize (runs doctor preflight checks). With no config file, the
//    backend resolves to the safe `file` backend on every platform — never
//    your real OS credential store. `vault.activeBackendType` is "file".
//    To opt into the native store, pass an explicit config with
//    `{ type: 'keychain' }` (macOS) / `{ type: 'dpapi' }` (Windows).
const vault = await VaultKeeper.init()

// 2. Store a secret in the configured backend
await vault.store('MY_API_KEY', 'my-secret-value')

// 3. Mint a JWE token for the stored secret
const jwe = await vault.setup('MY_API_KEY')

// 4. Authorize: decrypt and validate the token
const { token, vaultResponse } = await vault.authorize(jwe)

// 5. Delegated fetch — secret injected into the request, never returned
const { response } = await vault.fetch(token, {
  url: 'https://api.example.com/data',
  headers: { Authorization: 'Bearer {{secret}}' },
})
```

Other access patterns — delegated `exec()` (secret injected via env var) and controlled direct
access via `getSecret()` (auto-zeroing buffer) — are documented in the repo README linked below.

## Backends

The first enabled backend in the configuration is used. With no config file, that is the safe
`file` backend (AES-256-GCM encrypted file, all platforms, no system dependencies) — the zero-config
default on every platform. Configure a different backend explicitly to opt in: `keychain` (macOS),
`dpapi` (Windows), or `secret-tool` (Linux, via `libsecret`). Plugin backends for 1Password and
YubiKey are also available.

With no explicit `path`, the `file` backend stores secrets under `<configDir>/file/` — the same
resolved config directory (`~/.config/vaultkeeper` by default) that holds `config.json` and key
material.

## Testing against this library

Use [`@vaultkeeper/test-helpers`](https://www.npmjs.com/package/@vaultkeeper/test-helpers) for an
in-memory backend with zero OS dependencies in your own test suite.

## Full documentation

Access patterns, key rotation, trust tiers, development mode, configuration reference, and the
full error hierarchy are documented in the
[repository README](https://github.com/mike-north/vaultkeeper#readme).

## License

MIT
