# vaultkeeper

This is the library only — it has no `bin` and installs no `vaultkeeper` command. For the CLI
(`vaultkeeper config init`, `vaultkeeper doctor`, etc.), install the separate
[`@vaultkeeper/cli`](https://www.npmjs.com/package/@vaultkeeper/cli) package.

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

vaultkeeper is ESM-only. The consuming project needs `"type": "module"` in its `package.json`
(or an ESM-capable loader/bundler) for the `import` below to work — a default `npm init -y`
project is CommonJS and will need that field added first.

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

// 3. Mint a JWE token for the stored secret. Optional setup options
//    (ttlMinutes, useLimit, trustTier, ...) may be passed as a second
//    argument; useLimit defaults to unlimited (null) when omitted.
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
access via `getSecret()` (auto-zeroing buffer) — share the same `{{secret}}` placeholder substitution
shown above; see the `SecretAccessor` and `ExecRequest` types in the package's shipped `.d.ts` for
their full signatures.

## Example config

`VaultKeeper.init()` works with no config file (it resolves to the safe `file` backend). To pin
the configuration explicitly — e.g. to set a non-default TTL or trust tier — write a config file
matching this shape. This example is safe-by-default: it uses the portable `file` backend, not
your OS credential store.

```json
{
  "version": 1,
  "backends": [{ "type": "file", "enabled": true }],
  "keyRotation": { "gracePeriodDays": 7 },
  "defaults": { "ttlMinutes": 60, "trustTier": 3 }
}
```

- `backends` — ordered list of backend configs; whichever entry is **first** with `"enabled": true`
  becomes the single active backend — there's no automatic fallback to a later entry. To switch to
  an OS-native store, put an entry with `"type": "keychain"` (macOS), `"dpapi"` (Windows), or
  `"secret-tool"` (Linux) ahead of (or in place of) the `file` entry.
- `keyRotation.gracePeriodDays` — how many days the previous encryption key stays valid for
  decrypting existing tokens after `rotateKey()` runs; see [Key rotation](#key-rotation) below.
- `defaults.ttlMinutes` / `defaults.trustTier` — applied to `setup()` when its options don't
  override them; see [Trust tiers](#trust-tiers) below.

The full field reference is documented on the `VaultConfig` interface in the package's shipped
`.d.ts` (`vaultkeeper/dist/*.d.ts`).

## Key rotation

`rotateKey()` replaces the active encryption key but keeps the previous one valid for decryption
for `keyRotation.gracePeriodDays` days, so tokens minted before a rotation don't break immediately.
Once the grace period elapses, the retired key is dropped and JWEs encrypted under it can no
longer be decrypted.

## Trust tiers

Executable identity is verified during `setup()` against a local trust-on-first-use (TOFU)
manifest: a caller executable's hash is either already approved (trusted), unrecognized (first
encounter, recorded automatically), or changed since it was approved (a conflict, which rejects
the call until re-approved via `approveExecutable()`). Separately, `trustTier` (`1`, `2`, or `3`)
is a policy **label** attached to the resulting token — it does not itself reflect the outcome of
that verification. It defaults to `defaults.trustTier` from the config and can be overridden per
call via `setup()`'s `trustTier` option.

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

The package's shipped `.d.ts` files carry the complete API reference (every type, method, and
option, with JSDoc). For narrative coverage of development mode and the full error hierarchy
beyond what's inlined above, see the
[repository README](https://github.com/mike-north/vaultkeeper#readme).

## License

MIT
