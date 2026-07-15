# @vaultkeeper/wasm

WASM-backed [vaultkeeper](https://www.npmjs.com/package/vaultkeeper) SDK for Node.js. Wraps the
Rust `vaultkeeper-core` compiled to WebAssembly, with a Node.js host platform bridge for file I/O
and subprocess execution.

The public API is not a drop-in replacement for the TypeScript library — some function signatures
differ (e.g. `setup(secretName, secretValue, ...)` here, vs. the TS library's
`setup(secretName, options?)`).

**`setup()` does not read from the backend.** This package's `setup(secretName, secretValue, options?)`
mints a JWE directly from the `secretValue` argument — it never calls `store()`/`retrieve()` or reads
whatever is already persisted under `secretName`. The TS library's `setup(secretName, options?)` has
no `secretValue` parameter at all and always reads the current value from the configured backend.
`store()` and `setup()` are independent operations here; calling `store()` first has no effect on
what `setup()` encapsulates.

## Installation

```sh
pnpm add @vaultkeeper/wasm
```

**Requirements:** Node >= 20.13.0

## Quick start

This package is **ESM-only** — it ships an `import`-only `exports` map and no CommonJS
build, so there is no `require()` fallback. The snippet below is ESM and requires
`"type": "module"` in your `package.json` (or an ESM-capable loader/bundler). A default
`npm init -y` project is CommonJS, so add that field first — otherwise Node rejects the
`import` line with `SyntaxError: Cannot use import statement outside a module`:

In `package.json`:

```json
{
  "type": "module"
}
```

```ts
import { createVaultKeeper } from '@vaultkeeper/wasm'

const vault = await createVaultKeeper()

// Mint a JWE token directly from a value you already have — setup() does not
// read from the backend (see above), so no prior store() call is needed.
//
// setup() requires an explicit executable-trust choice: bind the calling
// executable's identity into the token, or deliberately skip that binding
// (development only). Omitting the choice throws ExecutableTrustRequiredError.
// With executablePath, setup() hashes that executable and records/checks it
// trust-on-first-use, throwing IdentityMismatchError if the hash changed from
// a previously approved value.
//
// IMPORTANT — do not point executablePath at a file you rebuild. Its content
// hash changes on every recompile/bundle, so `process.argv[1]` (your compiled
// entry file) throws IdentityMismatchError on the next run after any rebuild.
// For production, bind a STABLE anchor: `process.execPath` (the Node runtime)
// or the path to a released, unchanging binary. For local iterative dev, use
// `{ skipTrust: true }` (below) so a rebuild loop doesn't re-throw.
const jwe = await vault.setup('MY_API_KEY', 'my-secret-value', {
  executablePath: process.execPath, // production: a stable anchor (the Node runtime)
})
// …or, in development/tests only (no rebuild footgun):
// const jwe = await vault.setup('MY_API_KEY', 'my-secret-value', { skipTrust: true })

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

This package ships a committed `.wasm` binary — no `wasm-pack` install step required to consume it.

## Doctor / preflight checks

`vault.doctor()` runs the same preflight pass as the `vaultkeeper` library and CLI, returning a
`PreflightResult` whose per-dependency entries are classified **required** or **informational**
(see the [`vaultkeeper` README's "Doctor / preflight checks"](https://www.npmjs.com/package/vaultkeeper)
for the full model).

One WASM-specific caveat: this SDK persists secrets through the built-in **`file`** backend only —
it does not route through an OS-native credential store. But `doctor()` here runs the **unscoped**
preflight (it is not narrowed to the file backend the way `VaultKeeper.init()` narrows to your
configured backends), so the platform-native credential tool (`security` on macOS, `powershell` on
Windows, `secret-tool` on Linux) is still reported with `required: true`. For this SDK's file-backend
usage that entry is effectively an **inventory** signal, not a real readiness gate — a missing native
tool does not stop the SDK from working, because nothing here uses it. Only `openssl` (always
required) genuinely gates file-backend operation. Treat a failing native-tool entry from
`vault.doctor()` as informational unless you have separately arranged to use that OS store. (Scoping
the WASM `doctor()` to the file backend so this entry demotes to informational is tracked as a
follow-up; it needs a change to the Rust core and a rebuild of the committed `.wasm`.)

## Full documentation

See the [repository README](https://github.com/mike-north/vaultkeeper#readme) for the delegated
access patterns (fetch/exec) available in the pure TypeScript `vaultkeeper` library, which are
recommended over this package's lower-level `store()`/`retrieve()` APIs when avoiding raw secret
exposure in application memory matters.

## License

MIT
