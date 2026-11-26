---
'@vaultkeeper/wasm': patch
---

Honor the configured file backend storage path for secret operations.
Propagate inaccessible configuration errors instead of silently using the default store.
