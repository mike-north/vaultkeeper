# @vaultkeeper/wasm

## 0.2.1

### Patch Changes

- [#35](https://github.com/mike-north/vaultkeeper/pull/35) [`5a907e1`](https://github.com/mike-north/vaultkeeper/commit/5a907e138ba336dc7da140170950c93b1c7f43ee) Thanks [@mike-north](https://github.com/mike-north)! - Patch release to verify end-to-end publishing pipeline after release infrastructure fixes (crates.io gating, workspace dependency version sync, cross-platform compatibility)

## 0.2.0

### Minor Changes

- [#29](https://github.com/mike-north/vaultkeeper/pull/29) [`4a5314a`](https://github.com/mike-north/vaultkeeper/commit/4a5314a226ffeaef839b91338c062b14564486fb) Thanks [@mike-north](https://github.com/mike-north)! - Add WASM-backed SDK wrapping the Rust core compiled to WebAssembly. Provides createVaultKeeper factory, doctor checks, JWE token setup/authorize, key rotation/revocation, and secret store/retrieve/delete via a Node.js host platform bridge.
