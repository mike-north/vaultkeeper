---
'@vaultkeeper/wasm': patch
---

Document which WASM SDK methods are async vs. synchronous.

The `VaultKeeper` surface mixes Promise-returning methods (`setup`, `store`, `retrieve`, `delete`, `doctor`, and the `createVaultKeeper` factory) with synchronous ones (`authorize`, `config`, `rotateKey`, `revokeKey`, `dispose`), which was the root cause of the "forgot to `await` `setup()`" confusion. The README now includes an API methods table marking each method's kind, alongside the existing runtime guard that rejects a Promise passed where a string is expected.
