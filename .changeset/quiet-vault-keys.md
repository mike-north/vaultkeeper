---
'vaultkeeper': patch
'@vaultkeeper/wasm': patch
---

Serialize persisted token-key updates across native, TypeScript and WASM writers so an older vault cannot restore a revoked key or overwrite newer lease revocations.
