---
'vaultkeeper': patch
'@vaultkeeper/wasm': patch
---

Publish file-backed signing identities atomically without replacing an existing key. Concurrent first-time writers also reuse the wrapping key selected by the filesystem.
