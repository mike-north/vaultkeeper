# vaultkeeper

Unified, policy-enforced secret storage across OS backends. By default secrets are stored in a portable, self-contained AES-256-GCM encrypted file; your platform's native credential store (macOS Keychain, Windows DPAPI) is available as an explicit opt-in. Secrets are accessed through short-lived JWE tokens, and no secret ever appears in a return value — callers use delegated patterns that inject the value at the last possible moment.

Available as a **native Rust CLI**, a **TypeScript library**, a **WASM-backed SDK**, and a **Node.js CLI**.

<details>
<summary><strong>TL;DR — jump straight to the runnable bits</strong></summary>

The package matrix, install notes, and platform tables below are reference material. If you just
want working lines to copy:

- **CLI (shell/CI):** [`vaultkeeper` command quick start](#cli-usage)
- **TypeScript library:** [TypeScript quick start](#typescript-quick-start)
- **WASM SDK:** [WASM SDK quick start](#wasm-sdk-quick-start)

Minimal TypeScript-library flow (zero-config: safe `file` backend, no OS keychain touched; opt into keychain/DPAPI/`secret-tool` with a config file):

```ts
import { VaultKeeper } from 'vaultkeeper'

const vault = await VaultKeeper.init() // zero-config default: safe `file` backend when no config exists
await vault.store('MY_API_KEY', 'my-secret-value')
// `setup()` requires exactly one trust choice. `{ skipTrust: true }` (development
// only) keeps this snippet safe to re-run; in production bind a STABLE
// executablePath (a released binary, or process.execPath) — NOT process.argv[1],
// whose hash changes on every rebuild and would throw IdentityMismatchError on
// the next run. See "Trust and identity" below.
const jwe = await vault.setup('MY_API_KEY', { skipTrust: true })
const { token } = await vault.authorize(jwe)
await vault.fetch(token, {
  url: 'https://api.example.com/data',
  headers: { Authorization: 'Bearer {{secret}}' }, // secret injected, never returned
})
```

Minimal CLI flow:

```sh
vaultkeeper config init                       # safe default: file backend
echo "my-secret-value" | vaultkeeper store --name MY_API_KEY
vaultkeeper exec --secret MY_API_KEY --env API_KEY --caller /usr/local/bin/my-tool -- ./run.sh
```

</details>

## Which package should I use?

- **`vaultkeeper`** — the pure TypeScript library. Use this by default: it offers the delegated access patterns (`fetch()`, `exec()`, `getSecret()`) that keep raw secrets out of application memory. With no config file present it uses the safe `file` backend, same as the WASM SDK; `vaultkeeper config init` writes that same `file` default. To opt into your platform's native credential store instead, run `vaultkeeper config init --backend keychain` (macOS) / `--backend dpapi` (Windows), or set it in an explicit config.
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

**Supported TypeScript version:** tested against TypeScript 5.0.4–7.0.2 (the stated floor plus the latest release of the 5.x, 6.x, and 7.x majors). The guarantee is specifically that the shipped `.d.ts` files typecheck cleanly under the strict NodeNext consumer config below across that range — verified by a CI matrix (`packages/vaultkeeper/test/e2e/consumer-typecheck.test.ts`), so a future `.d.ts` change that breaks a tested version fails the build. The exact `compilerOptions` that matrix uses (verified known-good — copy these):

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

`types: []` scopes ambient globals to none (a common strict-monorepo pattern), so install `@types/node` as shown above — the shipped `.d.ts` resolves `Buffer` through its own import rather than an ambient global. The output relies on `verbatimModuleSyntax`; a bare `npm install -D typescript` within the tested range is fine.

The package ships both ESM (`import`) and CommonJS (`require()`) builds. The `exports` map selects the correct build automatically, but consumers still need the standard ESM/CJS project setup (e.g. `"type": "module"` for ESM) — see the [TypeScript quick start](#typescript-quick-start) below for both forms.

### WASM SDK

The WASM SDK wraps the Rust core compiled to WebAssembly. It offers a similar high-level feature set to the TypeScript library, but the public API is not a drop-in replacement — some function signatures differ (e.g., `setup(secretName, secretValue, ...)` vs the TS library's `setup(secretName, options?)`).

```sh
pnpm add @vaultkeeper/wasm
```

**Requirements:** Node >= 20.13.0

## CLI usage

Both the native Rust CLI and the Node.js CLI share the same command surface:

> [!NOTE]
> The safe `file` default described below (a bare `config init` writing the `file` backend) currently applies to the **Node.js CLI** and the TypeScript library. The native Rust CLI's zero-config default still targets the platform-native store; converging it onto this behavior is tracked in [#75](https://github.com/mike-north/vaultkeeper/issues/75).

```sh
# Run preflight checks
vaultkeeper doctor

# Initialize configuration. With no --backend the Node CLI writes the safe,
# portable `file` backend (never your real OS keychain). Opt into the native
# store explicitly with --backend, e.g.:
vaultkeeper config init                      # safe default: file backend
vaultkeeper config init --backend keychain   # opt in to the macOS Keychain

# Show current configuration
vaultkeeper config show

# Store a secret (reads from stdin)
echo "my-secret-value" | vaultkeeper store --name MY_API_KEY

# Delete a secret
vaultkeeper delete --name MY_API_KEY

# Enroll a signing key, then export its public half to pin/register elsewhere
vaultkeeper key create --name approval-signing-key --type ed25519
vaultkeeper key export --name approval-signing-key > approval.pub

# Sign an arbitrary challenge from stdin; stdout is exactly the detached
# signature (a compact JWS), so it is safe to redirect into a file
printf '%s' "$CHALLENGE" | vaultkeeper sign --name approval-signing-key > sig

# Verify a detached signature fully offline — only the public key, the payload
# on stdin, and the signature. Exit 0 = valid, 3 = did not verify.
vaultkeeper verify --public-key approval.pub --signature sig <<<"$CHALLENGE"

# Pre-approve an executable (TOFU): records its SHA-256 in the trust manifest
vaultkeeper approve --script /usr/local/bin/my-tool

# Enable (or disable) development mode for a script
vaultkeeper dev-mode enable --script /path/to/script

# Run a command with a secret injected into an env var (approve the caller first,
# above; see "Running in CI" below for the non-interactive form). By default the
# secret value is redacted from the command's stdout/stderr as `[REDACTED]` —
# pass --no-redact if you need to see the real output while debugging.
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

> [!NOTE]
> With no config file present, a bare `VaultKeeper.init()` — and `vaultkeeper config init` with no `--backend` — resolves to the safe, portable `file` backend on **every** platform. It never silently writes a secret to your real OS credential store, so copy-pasting this quick start is safe on macOS and Windows. To opt into the platform-native store (macOS Keychain, Windows DPAPI), pass an explicit config with that backend, or run `vaultkeeper config init --backend keychain` / `--backend dpapi`. Inspect `vault.activeBackendType` to confirm which backend an instance resolved to.

The example below uses ESM `import` syntax, which needs `"type": "module"` in your `package.json`
(a default `npm init -y` project is CommonJS and needs that field added). If you'd rather stay on
CommonJS, `require('vaultkeeper')` works unchanged — the package's `exports` map resolves to a CJS
build automatically; only the `import`/`await` syntax at the top level differs (wrap the body in an
`async function`, as CommonJS has no top-level `await`).

```ts
import { VaultKeeper } from 'vaultkeeper'

// 1. Initialize (runs doctor preflight checks)
//    With no config file, the backend resolves to the safe `file` backend on
//    every platform — never your real OS credential store. init() is a runtime,
//    in-memory operation: it loads built-in defaults and does NOT write a
//    config.json. To persist a config file on disk, use the CLI's
//    `vaultkeeper config init` (see "@vaultkeeper/cli").
const vault = await VaultKeeper.init()
console.log(vault.activeBackendType) // "file"

// Want your platform's native store (macOS Keychain, Windows DPAPI)? Opt in
// with an explicit config:
// const vault = await VaultKeeper.init({
//   config: {
//     version: 1,
//     backends: [{ type: 'keychain', enabled: true }],
//     keyRotation: { gracePeriodDays: 7 },
//     defaults: { ttlMinutes: 60, trustTier: 3 },
//   },
// })
// From the CLI, the equivalent is: vaultkeeper config init --backend keychain

// 2. Store a secret in the configured backend
await vault.store('MY_API_KEY', 'my-secret-value')

// 3. Mint a JWE token for the stored secret. `setup()` requires an explicit
//    executable-trust choice — exactly one of `executablePath` (Trust On First
//    Use verification) or `{ skipTrust: true }` (development opt-out); the type
//    system enforces this. `{ skipTrust: true }` is used here so the snippet is
//    safe to re-run. In PRODUCTION bind a STABLE `executablePath` (a released
//    binary, or `process.execPath` to trust the Node runtime) — NOT
//    `process.argv[1]` for a compiled entry point, whose hash changes on every
//    rebuild and throws `IdentityMismatchError` on the next run (see "Trust and
//    identity" / "Development mode").
const jwe = await vault.setup('MY_API_KEY', { skipTrust: true })

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

// 5c. Controlled direct access — buffer is zeroed after the callback returns.
// read() passes the callback's return value through, so you can derive a value
// (e.g. a header string or a hash) inside the callback and capture it. Never
// return the raw `buf` itself — it is zeroed before read() returns.
const accessor = vault.getSecret(token)
const authHeader = accessor.read((buf) => `Bearer ${buf.toString('utf8')}`)
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

const vault = await TestVault.create()
await vault.store('MY_API_KEY', 'my-secret-value')
// TestVault.setup() defaults to the development-only skipTrust opt-out so tests
// stay hermetic (no real executable to hash).
const jwe = await vault.setup('MY_API_KEY')
```

## WASM SDK quick start

The WASM SDK exposes lower-level APIs than the TypeScript library's delegated patterns. Methods like `store()` and `retrieve()` handle raw secret values directly — use the delegated access patterns (fetch/exec) from the TypeScript library when you need to avoid exposing secrets in application memory.

**The WASM SDK always uses the file backend.** Unlike the native and Node.js CLIs and the TypeScript library, it does not read the `backends` config and does not use the platform-default credential store (Keychain, DPAPI, `secret-tool`) — secrets are always stored in the AES-256-GCM encrypted file backend regardless of platform.

**`setup()` does not read from the backend.** `vault.setup(secretName, secretValue, options?)` mints a JWE directly from the `secretValue` argument you pass in — it never calls `store()`/`retrieve()` or looks at anything already persisted under `secretName`. This diverges from the TypeScript library's `vault.setup(secretName, options?)`, which has no `secretValue` parameter at all and always reads the current value from the configured backend. `store()` and `setup()` are independent operations here — calling `store()` first has no effect on what `setup()` encapsulates.

```ts
import { createVaultKeeper } from '@vaultkeeper/wasm'

const vault = await createVaultKeeper()

// Mint a JWE token directly from a value you already have — setup() does not
// read from the backend (see above), so no prior store() call is needed.
const jwe = vault.setup('MY_API_KEY', 'my-secret-value')

// Authorize: decrypt and validate. The result's `claims` never contain the
// raw secret — read it exactly once through the one-time accessor.
const result = vault.authorize(jwe)
const apiKey = result.secret.read((value) => value)

// store()/retrieve() are a separate, independent file-backend API — useful
// when you want the WASM SDK to persist a secret for later retrieval, but
// note that setup() above will not read what you stored here.
await vault.store('MY_API_KEY', apiKey)
const retrieved = await vault.retrieve('MY_API_KEY')
console.log(retrieved === apiKey) // true — same value, via the independent store()/retrieve() path

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

The **zero-config default is the `file` backend on every platform** — a bare `VaultKeeper.init()` or `vaultkeeper config init` (no `--backend`) never silently writes to your real OS credential store. Each platform additionally offers a native credential store you can **opt into** explicitly (`--backend <type>`, or an explicit config):

| Platform | Zero-config default | Native store (opt-in) | Opt-in dependencies                                              |
| -------- | ------------------- | --------------------- | ---------------------------------------------------------------- |
| macOS    | `file`              | `keychain`            | `security` (built-in)                                            |
| Windows  | `file`              | `dpapi`               | PowerShell (built-in)                                            |
| Linux    | `file`              | `secret-tool`         | `libsecret` / `secret-tool` (`sudo apt install libsecret-tools`) |
| Any      | `file`              | —                     | None (AES-256-GCM encrypted file, no OS credential store needed) |

The `file` backend works on all platforms and requires no system dependencies, which is why it is the safe default and a good fit for CI, Docker, and environments without a native credential store. With no explicit `path` configured, it stores secrets under `<configDir>/file/` — the same resolved config directory (`~/.config/vaultkeeper` by default, overridable via `--config-dir`/`VAULTKEEPER_CONFIG_DIR`) that holds `config.json` and key material, so everything lives in one discoverable place. Set `"path"` on the backend config to store secrets elsewhere instead.

To use the native Linux credential store instead, install `secret-tool` (`sudo apt install libsecret-tools`) and set `"type": "secret-tool"` in your config.

> **Upgrading from before this default changed:** the `file` backend's default storage directory moved from `$HOME/.vaultkeeper/file` to `<configDir>/file`. Existing secrets at the old location are still readable — `retrieve`/`exists`/`delete`/`list` fall back to it transparently when a secret isn't found at the new default — but `store` always writes to the new location going forward. Secrets you write after upgrading land in the new location; nothing at the old location is migrated automatically.

## Access patterns

> **These are TypeScript-library methods.** `fetch()`, `exec()`, `getSecret()`, and `sign()`/`verify()`
> below are methods on the `vaultkeeper` (TS library) `VaultKeeper` class. The
> [`@vaultkeeper/wasm`](#wasm-sdk-quick-start) SDK does **not** provide these delegated patterns — it
> exposes a different, lower-level surface (`store()`/`retrieve()` and a `setup()`/`authorize()` pair
> with different signatures; see [WASM SDK quick start](#wasm-sdk-quick-start)). Reach for the TS
> library when you need the delegated patterns that keep raw secrets out of application memory.

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

The returned `stdout`/`stderr` is **redacted by default**: every occurrence of an injected secret value in the captured output is replaced with `[REDACTED]`, so the raw secret never appears in the return value even if the spawned command echoes it. Pass `redact: false` to receive raw, unredacted output — only when a caller genuinely needs it, since that forfeits the guarantee.

```ts
const { result } = await vault.exec(token, {
  command: 'my-tool',
  args: ['run', '--config', '/etc/my-tool/config.yaml'],
  env: { API_KEY: '{{secret}}' },
  cwd: '/tmp',
})
console.log(result.stdout, result.exitCode) // any echoed secret shows as [REDACTED]
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

### Sign and verify

Signing keys are a **distinct resource from secrets**. A signing key's private half never flows through `store()`/`retrieve()`/`fetch()`/`exec()` or a capability token's claims — the backend generates the key, exposes only its public half, and performs each signature itself, so the key never leaves the backend. `verify()` is a **static** method that checks a detached signature against public key material and needs no `VaultKeeper` instance, backend, secret, or token.

The end-to-end flow — enroll a key, export its public half, sign an arbitrary caller-supplied payload, and verify:

```ts
// 1. Enroll a signing key (backend-side; only the `file` backend supports this today)
const { publicKeyPem, kid } = await vault.createSigningKey('approval-signing-key', 'EdDSA')

// 2. Export the SPKI PEM public key any time, to pin/register with a verifier
const pub = await vault.exportPublicKey('approval-signing-key')

// 3. Sign an arbitrary payload. authorizeSigningKey() mints a capability token
//    that carries only { kid, backendRef, keyType } — never key material.
const token = await vault.authorizeSigningKey('approval-signing-key')
const { result } = await vault.sign(token, { payload: 'gate1:abc123:1706000000' })
console.log(result.jws) // detached compact JWS: <protected>..<signature>

// 4. Verify, fully offline — only the payload, the JWS, and the public key
const isValid = await VaultKeeper.verify({
  payload: 'gate1:abc123:1706000000',
  jws: result.jws,
  publicKey: pub.publicKeyPem,
})
```

**Signature format (stable, documented, third-party-verifiable).** The output is a detached-payload Compact JWS — the three-tuple is:

- **algorithm** — `EdDSA` (Ed25519); the algorithm registry uses strict JOSE identifiers.
- **encoding** — base64url, no padding ([RFC 7515](https://www.rfc-editor.org/rfc/rfc7515)).
- **detachment** — detached payload via [RFC 7797](https://www.rfc-editor.org/rfc/rfc7797) `b64:false`, `crit:["b64"]`; the serialization is `<protected>..<signature>` with the payload omitted.

Any standards-compliant JOSE library can verify a vaultkeeper signature given the payload and the public key, with no dependency on vaultkeeper. `verify()` returns `false` for a signature that does not check out — a tampered payload, the wrong key, or a malformed JWS — and throws `InvalidKeyMaterialError` only when the public key itself is unparseable (an operational fault, distinct from a bad signature).

A backend that does not implement the signing contract fails with a typed `SigningNotSupportedError` naming the backends that do — signing is never silently emulated.

**End-to-end — generate a key, store it, sign, verify.** A complete round-trip, runnable as written:

```ts
import { generateKeyPairSync } from 'node:crypto'
import { VaultKeeper } from 'vaultkeeper'

// 1. Generate a key pair. The PRIVATE key (PEM) is the secret sign() needs;
//    the PUBLIC key (PEM) is what verify() checks the signature against.
const { privateKey, publicKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
})

const vault = await VaultKeeper.init()

// 2. Store the PEM private key as the secret — NOT a plain string.
await vault.store('SIGNING_KEY', privateKey)

// 3. Mint a capability token over it and authorize. `{ skipTrust: true }`
//    (development only) keeps this runnable on every rebuild; in production pass
//    a stable `executablePath` instead (see "Trust and identity").
const jwe = await vault.setup('SIGNING_KEY', { skipTrust: true })
const { token } = await vault.authorize(jwe)

// 4. Sign — the private key never leaves the vault.
const { result } = await vault.sign(token, { data: 'order-42:refund:1999' })

// 5. Verify with the PUBLIC key — static and synchronous.
const isValid = VaultKeeper.verify({
  data: 'order-42:refund:1999',
  signature: result.signature,
  publicKey,
})
console.log(isValid) // true
```

> **Note on `@vaultkeeper/wasm`:** `sign()`/`verify()` are TypeScript-library methods and are not part
> of the WASM SDK's surface. Relatedly, the two SDKs treat `executablePath` differently: this library's
> `setup()` **verifies** executable identity (TOFU — it hashes the binary and checks the trust
> manifest), while the WASM SDK records `executablePath` as a non-enforcing **claim label** only, with
> no hashing or verification. See [#165](https://github.com/mike-north/vaultkeeper/issues/165) for that
> parity gap.

## Doctor / preflight

`VaultKeeper.init()` runs preflight checks automatically. How doctor scopes those checks depends on whether it is given a backend set:

By default, `VaultKeeper.doctor()` / `runDoctor()` (called with no options) treats the platform-native tooling check as **required** — `security` on macOS, `powershell` on Windows, `secret-tool` on Linux — so a missing native tool can make `result.ready` false even on a file-only config. The plugin-backend tool checks (`op`, `ykman`) are informational (warnings, never failing `ready`). When doctor is **scoped** to specific backends via `{ backends }` or `{ configDir }` (as `VaultKeeper.init()` does), only the tooling for those backends is required and the rest become informational — so `init()` on a file-only config does not fail readiness for a missing `security`/`secret-tool`.

To run checks without initializing:

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

Executable identity is verified during `setup()` by hashing the executable (SHA-256) and checking that hash against a local trust manifest — this is a **TOFU (Trust On First Use)** model, not a package-registry or transparency-log lookup. `setup()` requires an explicit executable-trust choice and never skips verification by default: pass `executablePath` (the calling executable's real path) to verify it. Hashing is skipped — and identity is treated as unverified — only when you deliberately opt out with `{ skipTrust: true }` or when the executable has been registered via `setDevelopmentMode()`; see [Development mode](#development-mode). When an `executablePath` is verified, `setup()` produces one of three outcomes:

- **Not yet approved** — first encounter with this executable path. The hash is recorded in the trust manifest so the same binary is recognized next time.
- **Approved** — the executable's current hash matches what's recorded in the trust manifest (via `vaultkeeper approve --script <path>` or a prior `setup()` call).
- **Mismatch** — the executable's current hash differs from what's recorded (the binary was rebuilt or replaced). `setup()` throws `IdentityMismatchError`; re-approve with `vaultkeeper approve --script <caller>`.

> **Choose a stable anchor for `executablePath` — do not use `process.argv[1]` for a compiled or bundled entry point.** Because verification is a content hash, binding to a dev build target means the FIRST run records the hash and the NEXT run (after any source edit + recompile) hits the **Mismatch** case above and throws `IdentityMismatchError`. In production point `executablePath` at a **stable** artifact — a released/installed binary (e.g. `/usr/local/bin/my-tool`), or `process.execPath` to trust the Node runtime itself. For a local caller you rebuild frequently but still want to verify, use [Development mode](#development-mode) rather than `skipTrust`. The trust choice is also type-enforced: `SetupOptions` requires exactly one of `executablePath` or `skipTrust: true`, so `setup('NAME')` and `setup('NAME', {})` are compile-time errors.

A `trustTier` value (`1`, `2`, or `3`) can also be attached to the resulting token as a policy label, independent of the TOFU check above.

> **Note:** `trustTier` is recorded in the token claims as a label only — it does not select or change which verification mechanism runs; every `setup()` call that actually hashes the executable (i.e. not a dev-mode call, see above) applies the same TOFU check regardless of the `trustTier` value passed. Tier `1` is reserved for a possible future Sigstore-based verification path; the codebase contains a Sigstore integration point, but it is currently a stub that always falls through to the TOFU check — no executable is verified via Sigstore or any package registry today. Tier `2` does not correspond to a registry signature check either; it is simply the "hash found in the trust manifest" case of the same TOFU model as tier `3`.

Pass `trustTier` in setup options to set that policy label:

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

// Or opt out of verification for a single call with the explicit, greppable
// escape hatch. Development only — a token minted this way carries no
// executable identity binding, so any process holding the JWE can redeem it.
const jwe = await vault.setup('MY_API_KEY', { skipTrust: true })
```

## Testing

The `@vaultkeeper/test-helpers` package provides an in-memory backend and a pre-configured `TestVault` for fast, hermetic tests with zero system dependencies:

```sh
pnpm add -D @vaultkeeper/test-helpers
```

```ts
import { TestVault } from '@vaultkeeper/test-helpers'

const vault = await TestVault.create()
await vault.store('MY_SECRET', 'hunter2')

const jwe = await vault.setup('MY_SECRET')
const { token } = await vault.keeper.authorize(jwe)
const { result } = await vault.keeper.exec(token, {
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
  // Production code should pass `{ executablePath: process.argv[1] }` to enforce
  // executable trust; this dependency-injection example uses the development-only
  // `skipTrust` opt-out so the test below stays hermetic.
  const jwe = await vault.setup(secretName, { skipTrust: true })
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
  // Production code should pass `{ executablePath: process.argv[1] }` to enforce
  // executable trust; this dependency-injection example uses the development-only
  // `skipTrust` opt-out so the test below stays hermetic.
  const jwe = await vault.setup(secretName, { skipTrust: true })
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
// Embedder/test context: skip executable-trust verification. Pass
// `{ executablePath }` instead in production to enforce it.
const jwe = await vault.setup('MY_SECRET', { skipTrust: true })
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

You must make an explicit executable-trust choice — provide exactly one of
`executablePath` (verify the caller) or `skipTrust: true` (development-only opt-out).
Supplying neither, or both, throws `ExecutableTrustRequiredError`. The remaining fields
are optional; omitting `useLimit` defaults it to `null` (unlimited uses) rather than
single-use.

```ts
const jwe = await vault.setup('SECRET_NAME', {
  executablePath: '/path/to/caller', // verify the calling executable (TOFU)
  // skipTrust: true,                 // OR deliberately skip verification (dev only) — mutually exclusive
  ttlMinutes: 30, // token TTL (default: from config)
  useLimit: 1, // null for unlimited (the default when omitted)
  trustTier: 3,
  backendType: 'keychain',
})
```

## Error types

All errors extend `VaultError`. The `@vaultkeeper/wasm` package exports and throws a subset of this hierarchy (see the "In `@vaultkeeper/wasm`" column) — errors tied to platform credential-store integration or executable-identity checks that don't apply to the WASM SDK's file-backend-only, lower-level surface are TS-library-only.

| Class                          | When thrown                                                                                                                                          | In `@vaultkeeper/wasm` |
| ------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------- | :--------------------: |
| `BackendLockedError`           | Keychain or credential store is locked                                                                                                               |    TS-library-only     |
| `DeviceNotPresentError`        | Required hardware device not connected                                                                                                               |    TS-library-only     |
| `AuthorizationDeniedError`     | User denied an OS permission dialog                                                                                                                  |    TS-library-only     |
| `BackendUnavailableError`      | No configured backend is reachable                                                                                                                   |    TS-library-only     |
| `PluginNotFoundError`          | A required plugin binary is not installed                                                                                                            |    TS-library-only     |
| `SecretNotFoundError`          | Secret does not exist in the backend                                                                                                                 |          Yes           |
| `TokenExpiredError`            | JWE has passed its `exp` claim                                                                                                                       |          Yes           |
| `KeyRotatedError`              | Key exited grace period; JWE is permanently unreadable                                                                                               |          Yes           |
| `KeyRevokedError`              | Key was explicitly revoked                                                                                                                           |          Yes           |
| `TokenRevokedError`            | Token has been blocked (e.g. single-use token already consumed)                                                                                      |          Yes           |
| `UsageLimitExceededError`      | Token presented more times than its `use` limit allows                                                                                               |          Yes           |
| `IdentityMismatchError`        | Executable hash changed since TOFU approval                                                                                                          |    TS-library-only     |
| `ExecutableTrustRequiredError` | `setup()` called without an explicit executable-trust choice (neither `executablePath` nor `skipTrust: true`, or both)                               |    TS-library-only     |
| `ExecError`                    | `exec()` request was invalid (e.g. `{{secret}}` in the `command` or `args` field) or the command could not be started (not found or failed to spawn) |    TS-library-only     |
| `InvalidTokenError`            | JWE could not be decrypted or validated (e.g. structurally malformed, tampered, or failed decryption)                                                |          Yes           |
| `AccessorConsumedError`        | `SecretAccessor.read()` called after already consumed                                                                                                |          Yes           |
| `InvalidAlgorithmError`        | `createSigningKey()` with an unsupported signing algorithm (strict JOSE identifiers; only `EdDSA` today)                                             |    TS-library-only     |
| `InvalidKeyMaterialError`      | `verify()` given an unparseable public key (an operational fault, distinct from a signature that simply does not verify)                             |    TS-library-only     |
| `SigningKeyNotFoundError`      | A named signing key does not exist; distinct from `SecretNotFoundError` (signing keys occupy their own namespace)                                    |    TS-library-only     |
| `SigningKeyAlreadyExistsError` | `key create` was asked to enroll a signing key whose name already exists; enrollment never overwrites (that would break pinned public keys)          |    TS-library-only     |
| `SigningNotSupportedError`     | The active backend does not implement the signing contract; names the backends that do (the `file` backend today)                                    |    TS-library-only     |
| `SetupError`                   | Required system dependency missing or incompatible at init                                                                                           |    TS-library-only     |
| `FilesystemError`              | Config directory not readable or writable                                                                                                            |    TS-library-only     |
| `RotationInProgressError`      | `rotateKey()` called while previous key is still in grace period                                                                                     |          Yes           |

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

MIT
