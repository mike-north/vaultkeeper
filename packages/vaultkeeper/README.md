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

**Requirements:** Node >= 20. **TypeScript version:** tested against TypeScript 5.0.4–7.0.2 (the stated floor plus the latest release of the 5.x, 6.x, and 7.x majors) — all typecheck cleanly against the shipped `.d.ts` files (the output relies on `verbatimModuleSyntax`). A bare `npm install -D typescript` is fine; this range is verified by a CI matrix (`packages/vaultkeeper/test/e2e/consumer-typecheck.test.ts`) so a future `.d.ts` change that breaks a tested version fails the build.

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

// 3. Mint a JWE token for the stored secret. `setup()` requires an explicit
//    executable-trust choice: pass `executablePath` to verify the caller
//    (Trust On First Use), or `{ skipTrust: true }` to skip verification in
//    development. Other options (ttlMinutes, useLimit, trustTier, ...) are
//    optional; useLimit defaults to unlimited (null) when omitted.
const jwe = await vault.setup('MY_API_KEY', { executablePath: process.argv[1] })

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
  const jwe = await vault.setup('MY_API_KEY', { executablePath: process.argv[1] })
  const { token } = await vault.authorize(jwe)
  const { response } = await vault.fetch(token, {
    url: 'https://api.example.com/data',
    headers: { Authorization: 'Bearer {{secret}}' },
  })
}

main()
```

Other access patterns share the same capability-token flow (`setup()` → `authorize()`):

**Delegated `exec()`** injects the secret into a child process's environment — never its `argv`,
which is visible to other processes via `ps`. Placeholders are substituted in `env` values only
(passing `{{secret}}` in `command`/`args` throws `ExecError`):

```ts
// `token` comes from authorize(), exactly like the fetch() example above.
const { result } = await vault.exec(token, {
  command: 'curl',
  args: ['-sS', 'https://api.example.com/data'],
  env: { API_KEY: 'Bearer {{secret}}' }, // {{secret}} resolved just before spawn
})
console.log(result.stdout, result.exitCode)
```

**Controlled direct access** via `getSecret()` is different — it returns a `SecretAccessor` whose
secret is only reachable through a single-use `read(callback)` call backed by an auto-zeroing
buffer; no placeholder substitution is involved. `sign()`/`verify()` are a fourth pattern for
signing/verifying data with a stored private key without ever exposing it — see
[Signing and verification](#signing-and-verification) below. See the `SecretAccessor` and
`ExecRequest` types in the package's shipped `.d.ts` for their full signatures.

## Multiple secrets in one request

`fetch()` and `exec()` accept either a single `CapabilityToken` or a `SecretTokenMap`
(`Record<string, CapabilityToken>`) to inject several secrets into one call. With a map, reference
each secret by the **named** placeholder `{{secret:<name>}}`, where `<name>` is a key in the map,
instead of the bare `{{secret}}`:

```ts
// Authorize each secret independently, then key the tokens by the names you'll
// reference in placeholders.
const apiJwe = await vault.setup('API_KEY', { executablePath: process.argv[1] })
const dbJwe = await vault.setup('DB_PASSWORD', { executablePath: process.argv[1] })
const { token: apiToken } = await vault.authorize(apiJwe)
const { token: dbToken } = await vault.authorize(dbJwe)

const { response } = await vault.fetch(
  { apiKey: apiToken, dbPassword: dbToken },
  {
    url: 'https://api.example.com/data',
    headers: { Authorization: 'Bearer {{secret:apiKey}}' },
    body: JSON.stringify({ db: '{{secret:dbPassword}}' }),
  },
)
```

The same map and `{{secret:name}}` syntax work for `exec()` env values. A `{{secret:name}}` whose
`name` is not a key in the map fails the call, but the error type differs by method: `fetch()`
surfaces the underlying `VaultError`, while `exec()` wraps that same failure as an `ExecError`. The
two modes don't mix within a single call: a single-token call resolves only `{{secret}}`, and a map
call resolves only `{{secret:name}}`.

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

### Full `VaultConfig` reference

Every field of the config object (the `VaultConfig` interface, also carried on the package's
shipped `.d.ts`):

| Field                         | Type              | Required | Meaning                                                                                                    |
| ----------------------------- | ----------------- | -------- | ---------------------------------------------------------------------------------------------------------- |
| `version`                     | `number`          | yes      | Config schema version. Currently must be `1`.                                                              |
| `backends`                    | `BackendConfig[]` | yes      | Ordered backend list; the **first** entry with `enabled: true` is the single active backend (no fallback). |
| `keyRotation.gracePeriodDays` | `number`          | yes      | Days the previous key stays valid for decryption after `rotateKey()` before it is retired.                 |
| `defaults.ttlMinutes`         | `number`          | yes      | Default JWE time-to-live applied by `setup()` when its `ttlMinutes` option is omitted.                     |
| `defaults.trustTier`          | `1 \| 2 \| 3`     | yes      | Default policy trust-tier label applied by `setup()` when its `trustTier` option is omitted.               |
| `developmentMode.executables` | `string[]`        | no       | Executable paths exempted from TOFU identity verification (see [Development mode](#development-mode)).     |

Each `BackendConfig` entry in `backends`:

| Field     | Type                     | Required | Meaning                                                                                           |
| --------- | ------------------------ | -------- | ------------------------------------------------------------------------------------------------- |
| `type`    | `string`                 | yes      | Backend type: `'file'`, `'keychain'`, `'dpapi'`, `'secret-tool'`, `'1password'`, `'yubikey'`.     |
| `enabled` | `boolean`                | yes      | Whether this backend is active. Only enabled backends are considered during initialization.       |
| `plugin`  | `boolean`                | no       | `true` for plugin-provided backends (1Password, YubiKey) rather than built-in ones.               |
| `path`    | `string`                 | no       | Storage directory for file-based backends. Defaults to `<configDir>/file` for the `file` backend. |
| `options` | `Record<string, string>` | no       | Backend-specific options collected during interactive setup.                                      |

## Key rotation

`rotateKey()` replaces the active encryption key but keeps the previous one valid for decryption
for `keyRotation.gracePeriodDays` days, so tokens minted before a rotation don't break immediately.
Once the grace period elapses, the retired key is dropped and JWEs encrypted under it can no
longer be decrypted.

## Trust tiers

In this TypeScript library, executable identity verification against a local trust-on-first-use
(TOFU) manifest runs when `VaultKeeper.setup()` is given a real `executablePath`. **This library's
`setup()` requires an explicit executable-trust choice — it has no default and never silently skips
verification.** (The separate [`@vaultkeeper/wasm`](https://www.npmjs.com/package/@vaultkeeper/wasm)
SDK also requires the explicit choice, but records `executablePath` as a claim label without running
TOFU verification — see that package's API reference.) Pass the caller's real path to
protect a production caller: `vault.setup('MY_API_KEY', { executablePath: '/usr/local/bin/my-tool'
})`. To deliberately skip verification during development, pass the explicit, greppable opt-out
`vault.setup('MY_API_KEY', { skipTrust: true })` instead — a token minted this way carries no
executable identity binding, so use it only in local development or tests, never in production.
Calling `setup()` with neither option (or both) throws `ExecutableTrustRequiredError`. Once a real
path is passed, the caller's hash is either already approved (trusted), unrecognized (first
encounter, recorded automatically), or changed since it was approved (a conflict, which rejects the
call until re-approved via `approveExecutable()`). Separately, `trustTier` (`1`, `2`, or `3`) is a
policy **label** attached to the resulting token — it does not itself reflect the outcome of that
verification, and it has no effect when verification is skipped via `skipTrust`. It defaults to
`defaults.trustTier` from the config and can be overridden per call via `setup()`'s `trustTier`
option.

## Development mode

The `setDevelopmentMode` allowlist is a second, separate way to bypass the TOFU check above for a
_specific_ executable path — distinct from the per-call `{ skipTrust: true }` opt-out (which names
no path and binds no executable identity). Use the allowlist when you want to keep passing a real
`executablePath` (so a later `setDevelopmentMode(path, false)` re-enables verification for it) while
a binary that's rebuilt frequently during local development doesn't get rejected as an
`IdentityMismatchError` every time its hash changes. Add an executable with `await vault.setDevelopmentMode(path, true)` (persisted in
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

The disallowed-algorithm throw applies only to RSA and EC keys. For **Ed25519 / Ed448** keys the
signing algorithm is implicit in the key itself, so a `request.algorithm` override is ignored and
an otherwise-disallowed value does **not** throw `InvalidAlgorithmError` — the same caveat applies
to `sign()`.

## Backends

The first enabled backend in the configuration is used. With no config file, that is the safe
`file` backend (AES-256-GCM encrypted file, all platforms, no system dependencies) — the zero-config
default on every platform. Configure a different backend explicitly to opt in: `keychain` (macOS),
`dpapi` (Windows), or `secret-tool` (Linux, via `libsecret`). Plugin backends for 1Password and
YubiKey are also available.

With no explicit `path`, the `file` backend stores secrets under `<configDir>/file` — the same
resolved config directory (`~/.config/vaultkeeper` by default) that holds `config.json` and key
material.

## Doctor / preflight checks

`VaultKeeper.init()` runs a preflight check pass (the same checks the `runDoctor()` export and the
CLI's `vaultkeeper doctor` / WASM `doctor()` surface). Each check reports whether a dependency
binary was found, and every result is classified **required** or **informational**:

- **Required** checks gate readiness. A required check that fails makes the overall result
  **not ready** and produces a remediation next-step. `openssl` is always required. By default —
  when `runDoctor()` is not scoped to a set of backends — the platform's native credential tool
  (`security` on macOS, `powershell` on Windows, `secret-tool` on Linux) is **also required**;
  scoping the run to specific backends (e.g. via the `backends`/`configDir` inputs, as
  `VaultKeeper.init()` does from your config) narrows that to only the native tool for an enabled
  backend, demoting the others to informational.
- **Informational** checks never fail readiness — a failure is reported as a **warning** only.
  The plugin-backend binaries `op` (1Password) and `ykman` (YubiKey) are always listed but stay
  informational only while their backend isn't enabled. So with just the default `file` backend
  enabled, `op`/`ykman` still appear in the output and a failing one will not block `ready`. But
  enabling the corresponding backend (`1password` → `op`, `yubikey` → `ykman`) **promotes that
  check to required**, so a missing tool then does block `ready`.

A checkmark next to a plugin check therefore means **the binary was detected on `PATH`**, not that
the backend is active or configured — e.g. a green `op` means the 1Password CLI is installed, not
that a 1Password backend is enabled. To actually route secrets through a plugin backend you must
add it to `backends` (see [Backends](#backends)).

## Error types

Every error this package throws extends `VaultError`. Catch `VaultError` to handle any of them
generically, or catch a specific subclass for targeted handling. The complete hierarchy — every
subclass, grouped by concern — follows. Classes listing extra fields expose them as strongly-typed
read-only properties for machine-readable context.

**Backend access**

| Class                      | When thrown                                                                                |
| -------------------------- | ------------------------------------------------------------------------------------------ |
| `SecretNotFoundError`      | Requested secret does not exist in the backend store.                                      |
| `BackendUnavailableError`  | No configured backend is available or reachable (fields: `reason`, `attempted`).           |
| `BackendLockedError`       | Backend/credential store is locked and needs an interactive unlock (field: `interactive`). |
| `DeviceNotPresentError`    | A required hardware device (e.g. YubiKey) is not connected (field: `timeoutMs`).           |
| `AuthorizationDeniedError` | The user explicitly denied an OS authorization prompt.                                     |
| `PluginNotFoundError`      | A required backend plugin is not installed (fields: `plugin`, `installUrl`).               |

**JWE / token lifecycle**

| Class                     | When thrown                                                                         |
| ------------------------- | ----------------------------------------------------------------------------------- |
| `TokenExpiredError`       | JWE has passed its `exp` claim (field: `canRefresh`).                               |
| `KeyRotatedError`         | Encryption key rotated out of its grace period; the JWE can no longer be decrypted. |
| `KeyRevokedError`         | Encryption key referenced by the JWE's `kid` header was explicitly revoked.         |
| `TokenRevokedError`       | JWE was explicitly blocked (e.g. a single-use token that was already consumed).     |
| `UsageLimitExceededError` | Token was presented more times than its `use` limit allows.                         |
| `InvalidTokenError`       | JWE is malformed, fails decryption, or its decrypted claims do not validate.        |

**Identity & trust**

| Class                          | When thrown                                                                                                           |
| ------------------------------ | --------------------------------------------------------------------------------------------------------------------- |
| `IdentityMismatchError`        | Executable hash changed since TOFU approval (fields: `previousHash`, `currentHash`; see [Trust tiers](#trust-tiers)). |
| `ExecutableTrustRequiredError` | `setup()` called with no clear trust choice — neither `executablePath` nor `skipTrust` (field: `reason`).             |

**Access patterns**

| Class                     | When thrown                                                                                                                                                                       |
| ------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `FetchError`              | Delegated `fetch()` failed before a `Response` (malformed URL, network failure) (field: `url`).                                                                                   |
| `ExecError`               | `exec()` request was invalid, or the command could not be started (field: `command`).                                                                                             |
| `AccessorConsumedError`   | `SecretAccessor.read()` called after it was already consumed.                                                                                                                     |
| `InvalidAlgorithmError`   | Signing/verifying with a disallowed algorithm (fields: `algorithm`, `allowed`; see [Signing and verification](#signing-and-verification)).                                        |
| `InvalidKeyMaterialError` | `sign()` could not parse the stored secret as PEM/DER **private** key material. Specific to `sign()` — `VaultKeeper.verify()` does not read stored secrets and never throws this. |

**Config, filesystem & key rotation**

| Class                     | When thrown                                                                                              |
| ------------------------- | -------------------------------------------------------------------------------------------------------- |
| `DecryptionError`         | An encrypted-at-rest entry could not be decrypted (field: `path`).                                       |
| `ConfigValidationError`   | A config value failed structural/semantic validation (fields: `field`, `configFilePath`).                |
| `ConfigParseError`        | Config file contents are not valid JSON (fields: `path`, `location`).                                    |
| `SetupError`              | A required system dependency is missing or incompatible at init (field: `dependency`).                   |
| `FilesystemError`         | A filesystem operation failed — permission, ENOSPC, EISDIR, etc. (fields: `path`, `permission`, `code`). |
| `RotationInProgressError` | `rotateKey()` called while a previous rotation's grace period is still active.                           |

Each class's JSDoc (carried on the package's shipped `.d.ts`) documents these same errors and
fields inline. The [repository README](https://github.com/mike-north/vaultkeeper#readme) mirrors
this list for online reference.

## Testing against this library

Use [`@vaultkeeper/test-helpers`](https://www.npmjs.com/package/@vaultkeeper/test-helpers) for an
in-memory backend and a pre-configured `TestVault` with zero OS dependencies in your own test
suite. Install it as a **devDependency** — a combined `npm i vaultkeeper @vaultkeeper/test-helpers`
would place it in `dependencies`, so install it separately:

```sh
pnpm add -D @vaultkeeper/test-helpers
```

> **Note:** `TestVault` and its `setup()` convenience default the trust choice to `skipTrust` so
> tests stay hermetic. The real `VaultKeeper.setup()` has **no default** — it always requires
> either `executablePath` (TOFU verification) or an explicit `{ skipTrust: true }`, and throws
> `ExecutableTrustRequiredError` if given neither. Don't copy a bare `setup('NAME')` out of a test
> into non-test code (see [Trust tiers](#trust-tiers)).

## Full documentation

This README is self-contained: the full error hierarchy, development-mode narrative, and complete
`VaultConfig` reference above are all shipped inside the package (no network access required). The
package's `.d.ts` files carry the same reference on every exported type, method, and option via
JSDoc. The [repository README](https://github.com/mike-north/vaultkeeper#readme) mirrors this
content online as a supplement.

## License

MIT
