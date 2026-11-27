---
'@vaultkeeper/wasm': patch
---

Honor the configured file backend storage path for secret operations.
Propagate inaccessible configuration errors instead of silently using the default store.
Keep signing entries separate when a configured directory resolves to the vault's signing store.
