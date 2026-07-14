# @vaultkeeper/wasm

WASM-backed [vaultkeeper](https://www.npmjs.com/package/vaultkeeper) SDK for Node.js. Wraps the
Rust `vaultkeeper-core` compiled to WebAssembly, with a Node.js host platform bridge for file I/O
and subprocess execution.

The public API is not a drop-in replacement for the TypeScript library — some function signatures
differ (e.g. `setup(secretName, secretValue, ...)` here, vs. the TS library's
`setup(secretName, options?)`).

## Installation

```sh
pnpm add @vaultkeeper/wasm
```

**Requirements:** Node >= 20.13.0

## Quick start

```ts
import { createVaultKeeper } from '@vaultkeeper/wasm'

const vault = await createVaultKeeper()

// Store a secret
await vault.store('MY_API_KEY', 'my-secret-value')

// Mint a JWE token
const jwe = vault.setup('MY_API_KEY', 'my-secret-value')

// Authorize: decrypt and validate
const result = vault.authorize(jwe)

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
