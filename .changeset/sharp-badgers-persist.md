---
'@vaultkeeper/wasm': minor
---

Port encrypted key-state persistence (`keys.enc` + `.keys.wrap`) to the Rust core, closing the parity gap where the WASM SDK's `KeyManager` was memory-only. A JWE minted by one process (or `VaultKeeper` instance) is now authorized by a later one sharing the same config directory, and the rotation grace-period guard (`RotationInProgressError`) now survives a restart instead of resetting.

The on-disk format is byte-for-byte compatible with the pure-TypeScript `vaultkeeper` library's existing `keys/storage.ts`: a store written by either implementation loads correctly in the other.

Breaking (0.x): `rotateKey()` and `revokeKey()` are now async (`Promise<void>` instead of `void`), since persisting the new key state requires an I/O call. Versioned as a minor bump under 0.x semver (breaking changes ship as minor bumps while the SDK is pre-1.0).

```ts
// Before — synchronous:
vault.rotateKey()

// After — await the persisted rotation:
await vault.rotateKey()
```

The `WasmHostPlatform` interface consumed by `createNodeHost()` also gains a `renameFile(from, to)` method, used for atomic write-then-rename persistence.
