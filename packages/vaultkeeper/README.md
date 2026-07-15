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

**Requirements:** Node >= 20. Typechecking against the shipped `.d.ts` files requires TypeScript 5.x (the output relies on `verbatimModuleSyntax`). Install a 5.x compiler explicitly — `npm install -D typescript@5` — rather than a bare `npm install -D typescript`, which installs whatever major is current and may not be 5.x.

## Quick start

The package ships both ESM and CommonJS builds. The `exports` map selects the correct build
automatically, but consumers still need the standard ESM/CJS project setup (e.g.
`"type": "module"` for ESM) — see the two forms below.

**ESM** (`import`) — requires `"type": "module"` in your `package.json` (or an ESM-capable
loader/bundler); a default `npm init -y` project is CommonJS and needs that field added first:

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

**CommonJS** (`require()`) — the `exports` map resolves the same package to a CJS build
automatically, no `"type"` field needed:

```js
const { VaultKeeper } = require('vaultkeeper')

async function main() {
  const vault = await VaultKeeper.init()
  await vault.store('MY_API_KEY', 'my-secret-value')
  const jwe = await vault.setup('MY_API_KEY')
  const { token } = await vault.authorize(jwe)
  const { response } = await vault.fetch(token, {
    url: 'https://api.example.com/data',
    headers: { Authorization: 'Bearer {{secret}}' },
  })
}

main()
```

Other access patterns: delegated `exec()` (secret injected via env var) uses the same `{{secret}}`
placeholder substitution as `fetch()` above. Controlled direct access via `getSecret()` is
different — it returns a `SecretAccessor` whose secret is only reachable through a single-use
`read(callback)` call backed by an auto-zeroing buffer; no placeholder substitution is involved.
`sign()`/`verify()` are a fourth pattern for signing/verifying data with a stored private key
without ever exposing it — see [Signing and verification](#signing-and-verification) below.
See the `SecretAccessor` and `ExecRequest` types in the package's shipped `.d.ts` for their full
signatures.

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

Executable identity verification against a local trust-on-first-use (TOFU) manifest only runs
when `setup()` is given a real `executablePath`. **`setup()`'s `executablePath` option defaults to
`'dev'` when omitted, which skips verification entirely** — so the common/default call,
`vault.setup('MY_API_KEY')` with no options, is unverified by default. To protect a production
caller you must explicitly pass its path: `vault.setup('MY_API_KEY', { executablePath:
'/usr/local/bin/my-tool' })`. Once a real path is passed, the caller's hash is either already
approved (trusted), unrecognized (first encounter, recorded automatically), or changed since it
was approved (a conflict, which rejects the call until re-approved via `approveExecutable()`).
Separately, `trustTier` (`1`, `2`, or `3`) is a policy **label** attached to the resulting token —
it does not itself reflect the outcome of that verification, and it has no effect when
`executablePath` is left at its `'dev'` default. It defaults to `defaults.trustTier` from the
config and can be overridden per call via `setup()`'s `trustTier` option.

## Development mode

Development mode is a second, separate way to bypass the TOFU check above for a _specific_
executable path — useful when you want to keep passing a real `executablePath` (so a later
`setDevelopmentMode(path, false)` re-enables verification for it) while a binary that's rebuilt
frequently during local development doesn't get rejected as an `IdentityMismatchError` every time
its hash changes. Add an executable with `await vault.setDevelopmentMode(path, true)` (persisted in
`config.developmentMode.executables`). Only use this for local workflows — remove the executable
from the list (or don't add it) so a production caller stays on TOFU verification.

```ts
// Persist an executable as dev-mode-exempt across setup() calls, while still
// passing its real path (so re-enabling verification later is a one-line change):
await vault.setDevelopmentMode('/path/to/my-dev-tool', true)
const jwe = await vault.setup('MY_API_KEY', { executablePath: '/path/to/my-dev-tool' })

// Re-enable TOFU verification for that executable:
await vault.setDevelopmentMode('/path/to/my-dev-tool', false)
```

## Signing and verification

`sign()`/`verify()` are a fourth access pattern: they let you sign or verify data with a stored
private/public key without the private key ever leaving `VaultKeeper` internals.

```ts
// Sign — requires a capability token, like fetch()/exec()/getSecret()
const { result } = await vault.sign(token, { data: 'payload-to-sign' })
console.log(result.signature, result.algorithm) // base64 signature + algorithm label

// Verify — a static method: no VaultKeeper instance, secret, or token needed
const isValid = VaultKeeper.verify({
  data: 'payload-to-sign',
  signature: result.signature,
  publicKey: myPublicKeyPem,
})
```

`verify()` is synchronous and returns `false` for invalid key material, malformed signatures, or a
failed verification — except a disallowed algorithm (e.g. `'md5'`), which throws
`InvalidAlgorithmError` immediately (not via a rejected `Promise`), so wrap the call in a regular
`try`/`catch`, not `.catch()`.

## Backends

The first enabled backend in the configuration is used. With no config file, that is the safe
`file` backend (AES-256-GCM encrypted file, all platforms, no system dependencies) — the zero-config
default on every platform. Configure a different backend explicitly to opt in: `keychain` (macOS),
`dpapi` (Windows), or `secret-tool` (Linux, via `libsecret`). Plugin backends for 1Password and
YubiKey are also available.

With no explicit `path`, the `file` backend stores secrets under `<configDir>/file/` — the same
resolved config directory (`~/.config/vaultkeeper` by default) that holds `config.json` and key
material.

## Error types

Every error this package throws extends `VaultError`. Catch `VaultError` to handle any of them
generically, or catch a specific subclass for targeted handling. The most common ones:

| Class                   | When thrown                                                                                               |
| ----------------------- | --------------------------------------------------------------------------------------------------------- |
| `SecretNotFoundError`   | Secret does not exist in the backend                                                                      |
| `TokenExpiredError`     | JWE has passed its `exp` claim                                                                            |
| `IdentityMismatchError` | Executable hash changed since TOFU approval (see [Trust tiers](#trust-tiers))                             |
| `ExecError`             | `exec()` request was invalid, or the command could not be started                                         |
| `InvalidTokenError`     | JWE could not be decrypted or validated                                                                   |
| `AccessorConsumedError` | `SecretAccessor.read()` called after it was already consumed                                              |
| `InvalidAlgorithmError` | Signing/verifying with a disallowed algorithm (see [Signing and verification](#signing-and-verification)) |

The full hierarchy — covering backend, config, key-rotation, and filesystem failures too — is
documented on each class's JSDoc in the package's shipped `.d.ts`, and enumerated in the
[repository README](https://github.com/mike-north/vaultkeeper#readme).

## Testing against this library

Use [`@vaultkeeper/test-helpers`](https://www.npmjs.com/package/@vaultkeeper/test-helpers) for an
in-memory backend with zero OS dependencies in your own test suite.

## Full documentation

The package's shipped `.d.ts` files carry the complete API reference (every type, method, and
option, with JSDoc). For the exhaustive error class list and additional narrative detail beyond
what's inlined above, see the
[repository README](https://github.com/mike-north/vaultkeeper#readme).

## License

MIT
