---
'vaultkeeper': patch
'@vaultkeeper/wasm': patch
---

Serialize persisted token-key updates across native, TypeScript and WASM writers so an older vault cannot restore a revoked key or overwrite newer lease revocations.

Clear displaced TypeScript token-key buffers after publication while allowing in-flight token operations to finish with their own temporary key copies.
