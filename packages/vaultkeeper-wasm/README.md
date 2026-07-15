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

```ts
import { createVaultKeeper } from '@vaultkeeper/wasm'

const vault = await createVaultKeeper()

// Mint a JWE token directly from a value you already have — setup() does not
// read from the backend (see above), so no prior store() call is needed.
//
// setup() requires an explicit executable-trust choice: bind the calling
// executable's identity into the token, or deliberately skip that binding
// (development only). Omitting the choice throws ExecutableTrustRequiredError.
const jwe = vault.setup('MY_API_KEY', 'my-secret-value', {
  executablePath: process.argv[1], // production: bind to the calling executable
})
// …or, in development/tests only:
// const jwe = vault.setup('MY_API_KEY', 'my-secret-value', { skipTrust: true })

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

## Full documentation

See the [repository README](https://github.com/mike-north/vaultkeeper#readme) for the delegated
access patterns (fetch/exec) available in the pure TypeScript `vaultkeeper` library, which are
recommended over this package's lower-level `store()`/`retrieve()` APIs when avoiding raw secret
exposure in application memory matters.

## License

MIT
