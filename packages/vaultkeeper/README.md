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

**Requirements:** Node >= 20. **TypeScript version:** tested against TypeScript 5.0.4–7.0.2 (the stated floor plus the latest release of the 5.x, 6.x, and 7.x majors). The CI matrix (`packages/vaultkeeper/test/e2e/consumer-typecheck.test.ts`) verifies that the shipped `.d.ts` files typecheck cleanly under the strict NodeNext consumer config below across that version range, so a future `.d.ts` change that breaks a tested version fails the build. The exact `compilerOptions` that matrix uses (verified known-good — copy these):

```jsonc
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "strict": true,
    "skipLibCheck": false,
    "noEmit": true,
    "types": [],
  },
}
```

`types: []` scopes ambient globals to none (a common strict-monorepo pattern); because the public API references `Buffer`, install `@types/node` as a devDependency — the shipped `.d.ts` resolves `Buffer` through its own import rather than an ambient global. The output relies on `verbatimModuleSyntax`; a bare `npm install -D typescript` within the tested range is fine.

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
//    executable-trust choice — exactly one of `executablePath` or
//    `skipTrust: true` (the type system enforces this; omitting both, or
//    passing both, is a compile error). Other options (ttlMinutes, useLimit,
//    trustTier, ...) are optional; useLimit defaults to unlimited (null).
//
//    LOCAL DEVELOPMENT (used here so this snippet is safe to re-run): skip
//    verification with `{ skipTrust: true }`. It is safe to re-run after every
//    rebuild — the token just carries no executable-identity binding, so use it
//    only in development/tests, never in production.
const jwe = await vault.setup('MY_API_KEY', { skipTrust: true })

//    PRODUCTION: bind the token to a STABLE executable so a swapped or tampered
//    binary is rejected. Point `executablePath` at a released, stable artifact
//    (e.g. '/usr/local/bin/my-tool'), or at the Node runtime itself via
//    `process.execPath` ("trust the node binary").
//
//    ⚠️  Do NOT use `executablePath: process.argv[1]` for a compiled or bundled
//    entry point: its SHA-256 hash changes on every `tsc`/bundler rebuild, so
//    the FIRST run records the hash and the NEXT run (after any source edit +
//    recompile) throws `IdentityMismatchError`. For a caller you rebuild
//    frequently but still want to verify, use Development mode instead (see
//    "Development mode" below) rather than `skipTrust`.
//
// const jwe = await vault.setup('MY_API_KEY', { executablePath: '/usr/local/bin/my-tool' })

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
  // `{ skipTrust: true }` (development only) keeps this snippet safe to re-run;
  // for production bind to a stable executablePath instead — see the ESM step 3
  // above for the rebuild caveat and the production shape.
  const jwe = await vault.setup('MY_API_KEY', { skipTrust: true })
  const { token } = await vault.authorize(jwe)
  const { response } = await vault.fetch(token, {
    url: 'https://api.example.com/data',
    headers: { Authorization: 'Bearer {{secret}}' },
  })
}

main()
```

> **Scope:** the access patterns below — `fetch()`, `exec()`, `getSecret()`, and `sign()`/`verify()`
> — are methods of **this TypeScript library's** `VaultKeeper` class. The
> [`@vaultkeeper/wasm`](https://www.npmjs.com/package/@vaultkeeper/wasm) SDK exposes a different,
> lower-level surface (`store()`/`retrieve()` plus a `setup()`/`authorize()` pair with different
> signatures) and does **not** provide these delegated patterns — see that package's README.

Other access patterns share the same capability-token flow (`setup()` → `authorize()`):

**Delegated `exec()`** injects the secret into a child process's environment — never its `argv`,
which is visible to other processes via `ps`. Placeholders are substituted in `env` values only
(passing `{{secret}}` in `command`/`args` throws `ExecError`):

<!-- readme-example: skip - fragment; `vault`/`token` come from the quick-start fence above -->

```ts
// `token` comes from authorize(), exactly like the fetch() example above.
const { result } = await vault.exec(token, {
  command: 'curl',
  args: ['-sS', 'https://api.example.com/data'],
  env: { API_KEY: 'Bearer {{secret}}' }, // {{secret}} resolved just before spawn
})
console.log(result.stdout, result.exitCode)
```

**Output redaction (on by default).** If the child process echoes the injected secret, `exec()`
scrubs every occurrence of the secret value out of the captured `result.stdout` and `result.stderr`,
replacing each with `[REDACTED]` before returning — so the raw secret does not leak back through
captured output. This is the same redaction the [`@vaultkeeper/cli`](https://www.npmjs.com/package/@vaultkeeper/cli)
applies. With a `SecretTokenMap` (multiple secrets), **every** injected value is redacted. To opt
out and receive the raw, unredacted output — for example when you need to parse a payload that
legitimately contains the value — pass `redact: false` (mirroring the CLI's `--no-redact`):

<!-- readme-example: skip - fragment; `vault`/`token` come from the quick-start fence above -->

```ts
// Raw output — the injected secret is NOT scrubbed. Handle the result carefully;
// it may contain the secret verbatim.
const { result } = await vault.exec(token, {
  command: 'my-tool',
  env: { API_KEY: 'Bearer {{secret}}' },
  redact: false,
})
```

**Controlled direct access** via `getSecret()` is different — unlike `fetch()`/`exec()`, it does
**not** take a callback of its own and returns **synchronously**. It hands back a `SecretAccessor`
whose secret is only reachable through a single-use `read(callback)` call backed by an auto-zeroing
buffer; no placeholder substitution is involved. `read()` returns whatever the callback returns, so
derive the value you need (a header string, a hash) inside the callback and capture that — never the
raw `Buffer`, which is zeroed before `read()` returns. A second `read()` throws `AccessorConsumedError`:

<!-- readme-example: skip - fragment; `vault`/`token` come from the quick-start fence above -->

```ts
// `token` comes from authorize(), exactly like the fetch()/exec() examples above.
const accessor = vault.getSecret(token) // synchronous — no await, no callback here
const authHeader = accessor.read((buf) => `Bearer ${buf.toString('utf8')}`)
// `authHeader` is now the derived string; the underlying buffer is already zeroed.
// accessor.read(...) // <- calling read() again throws AccessorConsumedError
```

`createSigningKey()`/`sign()`/`verify()` are a fourth pattern: signing keys are a distinct resource
whose private half never leaves the backend, and signatures are detached-payload Compact JWS values
any JOSE library can verify — see [Signing and verification](#signing-and-verification) below. See
the `SecretAccessor` and `ExecRequest` types in the package's shipped `.d.ts` for their full
signatures.

## Multiple secrets in one request

`fetch()` and `exec()` accept either a single `CapabilityToken` or a `SecretTokenMap`
(`Record<string, CapabilityToken>`) to inject several secrets into one call. With a map, reference
each secret by the **named** placeholder `{{secret:<name>}}`, where `<name>` is a key in the map,
instead of the bare `{{secret}}`:

<!-- readme-example: skip - fragment; `vault` comes from the quick-start fence above -->

```ts
// Authorize each secret independently, then key the tokens by the names you'll
// reference in placeholders. `{ skipTrust: true }` (development only) is shown
// here; in production pass a stable `executablePath` instead — see
// [Trust tiers](#trust-tiers).
const apiJwe = await vault.setup('API_KEY', { skipTrust: true })
const dbJwe = await vault.setup('DB_PASSWORD', { skipTrust: true })
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

> **`VaultKeeper.init()` does not write a `config.json`.** `init()` is a **runtime, in-memory**
> operation: with no config file it loads built-in defaults into the process and writes nothing to
> disk (it only ever reads an existing config). To **persist** a `config.json` on disk, use the CLI
> `vaultkeeper config init` (from [`@vaultkeeper/cli`](https://www.npmjs.com/package/@vaultkeeper/cli)),
> which writes the file shown below. So `init()` never creates the config file — don't expect a
> `config.json` to appear after calling it; write one yourself (below) or run `config init`.

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
SDK also requires the explicit choice, but its `executablePath` is only a **claim label** — the WASM
`setup()` binds that path into the token without hashing the executable or running any TOFU
verification, so it does not detect a changed or unrecognized binary the way this library does. Only
this TypeScript library's `setup()` actually verifies executable identity. See that package's API
reference and [#165](https://github.com/mike-north/vaultkeeper/issues/165) for the parity gap.) Pass
the caller's real path to
protect a production caller: `vault.setup('MY_API_KEY', { executablePath: '/usr/local/bin/my-tool'
})`. To deliberately skip verification during development, pass the explicit, greppable opt-out
`vault.setup('MY_API_KEY', { skipTrust: true })` instead — a token minted this way carries no
executable identity binding, so use it only in local development or tests, never in production.
Calling `setup()` with neither option (or both) is rejected at **compile time** — the `SetupOptions`
type requires exactly one, and the options argument is mandatory, so `vault.setup('MY_API_KEY')` and
`vault.setup('MY_API_KEY', {})` fail to typecheck; `ExecutableTrustRequiredError` remains the runtime
backstop for untyped (plain-JavaScript) callers. Once a real
path is passed, the caller's hash is either already approved (trusted), unrecognized (first
encounter, recorded automatically), or changed since it was approved (a conflict, which rejects the
call until re-approved via `approveExecutable()`).

> **Approving a new caller — library vs. CLI.** In this library, a new caller's first `setup()` with
> a real `executablePath` is **recorded automatically** on first encounter (TOFU), so no separate
> approval step is required — there is no interactive prompt to answer. This differs from the
> [`@vaultkeeper/cli`](https://www.npmjs.com/package/@vaultkeeper/cli): its `exec` **prompts** to
> approve an unrecognized caller, and in a **non-interactive/CI** context (no TTY) that first `exec`
> **requires** a prior `vaultkeeper approve` (or `--yes`) — pre-approval there is a hard prerequisite,
> not just a prompt-avoidance convenience. Use `approveExecutable()` in this library to pre-record a
> caller ahead of time, or to re-approve after a hash conflict.

Separately, `trustTier` (`1`, `2`, or `3`) is a
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

<!-- readme-example: skip - fragment; `vault` comes from the quick-start fence above -->

```ts
// Persist an executable as dev-mode-exempt across setup() calls, while still
// passing its real path (so re-enabling verification later is a one-line change):
await vault.setDevelopmentMode('/path/to/my-dev-tool', true)
const jwe = await vault.setup('MY_API_KEY', { executablePath: '/path/to/my-dev-tool' })

// Re-enable TOFU verification for that executable:
await vault.setDevelopmentMode('/path/to/my-dev-tool', false)
```

## Signing and verification

Signing keys are a distinct resource from secrets. A signing key's private half never flows through
`store()`/`retrieve()`/`fetch()`/`exec()` or a capability token's claims: the backend generates the
key, exposes only its public half, and performs each signature itself, so the key never leaves the
backend. Signatures are detached-payload Compact JWS values verifiable by any JOSE library.

**Name rule.** Signing keys live under a reserved internal `signing-key:<name>` namespace, so a
secret name and a signing-key name can never collide. To keep that guarantee, name-creating and
name-binding calls — `store()`, `setup()`, `createSigningKey()`, `exportPublicKey()`,
`authorizeSigningKey()` — reject a `name` containing `':'` with a `VaultError`. Read/delete/existence
calls (`delete()`, `secretExists()`) stay permissive, so a legacy secret whose name happens to
contain `':'` remains reachable for inspection and cleanup.

<!-- readme-example: skip - fragment; `vault` comes from the quick-start fence above -->

```ts
// 1. Enroll a signing key (backend-side; the `file` backend supports this today)
const { publicKeyPem, kid } = await vault.createSigningKey('approval-signing-key', 'EdDSA')

// 2. Export the SPKI PEM public key any time
const pub = await vault.exportPublicKey('approval-signing-key')

// 3. Sign an arbitrary payload. authorizeSigningKey() mints a token carrying
//    only { kid, backendRef, keyType } — never key material.
const token = await vault.authorizeSigningKey('approval-signing-key')
const { result } = await vault.sign(token, { payload: 'payload-to-sign' })
console.log(result.jws) // detached compact JWS: <protected>..<signature>

// 4. Verify — a static, offline method: no instance, backend, secret, or token
const isValid = await VaultKeeper.verify({
  payload: 'payload-to-sign',
  jws: result.jws,
  publicKey: pub.publicKeyPem,
})
```

The signature format is a detached-payload Compact JWS — algorithm `EdDSA` (Ed25519); base64url
without padding ([RFC 7515](https://www.rfc-editor.org/rfc/rfc7515)); detached payload via
[RFC 7797](https://www.rfc-editor.org/rfc/rfc7797) `b64:false`, `crit:["b64"]` — so any
standards-compliant JOSE library can verify it without vaultkeeper. `verify()` returns `false` for a
signature that does not check out (tampered payload, wrong key, malformed JWS) and throws
`InvalidKeyMaterialError` only when the public key itself is unparseable. A backend that cannot sign
fails with a typed `SigningNotSupportedError` naming the backends that can — never a silent
emulation.

## Backends

The first enabled backend in the configuration is used. With no config file, that is the safe
`file` backend (AES-256-GCM encrypted file, all platforms, no system dependencies) — the zero-config
default on every platform. Configure a different backend explicitly to opt in: `keychain` (macOS),
`dpapi` (Windows), or `secret-tool` (Linux, via `libsecret`). Plugin backends for 1Password and
YubiKey are also available.

With no explicit `path`, the `file` backend stores secrets under `<configDir>/file` — the same
resolved config directory (`~/.config/vaultkeeper` by default) that holds `config.json` and key
material.

## Presence-per-use (require a fresh human action)

Some operations should only proceed when a **fresh, deliberate human action happens for that
operation, right now** — a distinct touch or biometric approval that can never be satisfied from a
cached or session-unlocked state. This is stronger than "a vault was unlocked at some point": a
cached unlock would let an automated or compromised caller ride a human action taken for something
else.

vaultkeeper models this as a per-configured-instance backend capability, `presencePerUse`, and lets
you require it for a specific operation.

**Query a backend's capabilities:**

<!-- readme-example: skip - fragment; `vault` comes from the quick-start fence above -->

```ts
const caps = await vault.getActiveBackendCapabilities()
if (!caps.presencePerUse) {
  // the active backend cannot force a fresh per-use action
}

// Or, for any backend instance, without assuming from its type:
import { getBackendCapabilities } from 'vaultkeeper'
const { presencePerUse } = await getBackendCapabilities(someBackend)
```

`getBackendCapabilities()` returns `{ presencePerUse: false }` for any backend that does not
implement the capability interface — an unknown backend never silently claims presence.

**Require it for an operation:** pass `requirePresencePerUse: true` to `store`, `delete`, `setup`,
or `sign`. When the active backend cannot guarantee it, the call throws `NotCapableError` **before
any credential, session, or device is touched**. When the backend is capable, the operation forces a
fresh human action for that specific call (a declined action throws `PresenceDeclinedError`; a
timeout throws `PresenceTimeoutError`):

<!-- readme-example: skip - fragment; `vault` comes from the quick-start fence above -->

```ts
// Presence-gated signing: each sign performs a fresh backend round-trip, so no
// cached key material can satisfy it (the private key never leaves the backend).
const token = await vault.authorizeSigningKey('approval')
const { result } = await vault.sign(token, { payload }, { requirePresencePerUse: true })
```

Capabilities are queried **fresh on every call** and never cached across operations, so two
consecutive required-presence operations each demand their own distinct fresh action.

### Per-backend truth basis

| Backend                                    | `presencePerUse`                                                                                         | Basis                                                                                                                                                                                                       |
| ------------------------------------------ | -------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `file`, `keychain`, `dpapi`, `secret-tool` | always `false`                                                                                           | Encryption-only or a cached/unattended unlock — no distinct per-use human action.                                                                                                                           |
| `yubikey`                                  | `true` only when the configured slot enforces touch-per-operation (`options.touchPolicy: "required"`)    | Every challenge-response forces a physical tap. Verify the slot's real policy with `ykman otp info`. Derived from configuration, never from the backend type.                                               |
| `1password`                                | `true` only in `per-access` mode (`options.accessMode: "per-access"`), and only for the `read` operation | A fresh worker/SDK client triggers a per-read biometric approval instead of reusing the cached session client. Writes route through the cached session, so it enforces presence for reads only (see below). |

> **Operation coverage (enforced, not advisory).** 1Password `per-access` forces a fresh biometric
> for **reads** (the secret read behind `setup`/`exec`) but routes `store`/`delete` through the cached
> session client. Enforcement is therefore **operation-aware and fail-closed**: a
> `--require-presence-per-use` / `requirePresencePerUse` `store` or `delete` on 1Password is **refused
> with `NotCapableError`** before any credential is touched — it never passes without a fresh action.
> Only presence-gated **reads** proceed. A touch device (YubiKey with a touch slot) enforces presence
> for every operation and has no such restriction. This is expressed generically via
> `BackendCapabilities.presenceEnforcedOperations` (omitted = all operations), not a per-type special
> case.

> **Cached-OS-unlock caveat.** A "fresh process / SDK client" is **not** the same as a guaranteed
> fresh hardware action. 1Password `per-access` re-creates the client per read, but the OS may still
> satisfy the biometric from a cached Touch ID / Windows Hello unlock without re-prompting — so its
> guarantee is "fresh SDK client plus whatever the OS enforces at that moment." The strongest per-use
> guarantee comes from a dedicated touch device (YubiKey / gpg smartcard), where the tap is intrinsic
> to the cryptographic operation.

Real-hardware confirmation for each backend is documented as a manual verification test in
[`docs/manual-tests/presence-per-use.md`](../../docs/manual-tests/presence-per-use.md).

## Doctor / preflight checks

`VaultKeeper.init()` runs a preflight check pass (the same checks the `runDoctor()` export and the
CLI's `vaultkeeper doctor` / WASM `doctor()` surface). Each check reports whether a dependency
binary was found, and every result is classified **required** or **informational**:

> **Why entries for backends you aren't using appear:** doctor probes the tooling for **all**
> supported backends, not just the active one — so even with only the `file` backend enabled you'll
> still see `security`/`op`/`ykman` entries. That's deliberate (an at-a-glance inventory of what's
> installed), not noise. Whether a given entry actually gates readiness follows the required-vs-
> informational split below: the plugin tools (`op`/`ykman`) stay informational until you enable
> their backend, while the platform-native tool (`security`/`powershell`/`secret-tool`) is required
> by default and demoted to informational only when the run is scoped to backends (as
> `VaultKeeper.init()` does).

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

| Class                          | When thrown                                                                                                                                                                                           |
| ------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `FetchError`                   | Delegated `fetch()` failed before a `Response` (malformed URL, network failure) (field: `url`).                                                                                                       |
| `ExecError`                    | `exec()` request was invalid, or the command could not be started (field: `command`).                                                                                                                 |
| `AccessorConsumedError`        | `SecretAccessor.read()` called after it was already consumed.                                                                                                                                         |
| `SigningKeyNotFoundError`      | A named signing key does not exist (field: `keyName`); distinct from `SecretNotFoundError` — signing keys occupy their own namespace (see [Signing and verification](#signing-and-verification)).     |
| `SigningKeyAlreadyExistsError` | Enrolling a signing key whose name already exists (field: `keyName`); enrollment never overwrites (that would break pinned public keys).                                                              |
| `SigningNotSupportedError`     | The active backend does not implement the signing contract; names the built-in backend that does — a custom backend may implement `SigningBackend` (fields: `backendType`, `builtInSigningBackends`). |
| `InvalidAlgorithmError`        | `createSigningKey()` with an unsupported signing algorithm — strict JOSE identifiers, only `EdDSA` today (fields: `algorithm`, `allowed`).                                                            |
| `InvalidKeyMaterialError`      | `verify()` given an unparseable public key, or a corrupt/tampered stored signing key — an operational fault, distinct from a signature that simply does not verify.                                   |

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
fields inline. The [repository README](https://github.com/mike-north/vaultkeeper#readme) covers
related narrative online, but this package's own README (above) and its shipped `.d.ts` are the
authoritative, complete list.

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
JSDoc. The [repository README](https://github.com/mike-north/vaultkeeper#readme) covers related
narrative online, but treat this package's own README as the complete, authoritative reference.

## License

MIT
