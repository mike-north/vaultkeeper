---
'vaultkeeper': patch
'@vaultkeeper/wasm': patch
---

Publish file-backed signing identities atomically without replacing an existing key. Concurrent first-time writers reuse the wrapping key selected by the filesystem, and a later writer can complete an interrupted wrapping-key repair using the selected key.
