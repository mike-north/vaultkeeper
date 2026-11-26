---
'vaultkeeper': patch
'@vaultkeeper/wasm': patch
---

Publish file-backed signing identities atomically without replacing an existing key. Concurrent first-time writers reuse the wrapping key selected by the filesystem, and a later writer can complete an interrupted wrapping-key repair using the selected key.

Ordinary storage continues to work on filesystems without hard links. Wrapping-key staging fits the supported macOS config path length during initialization and repair.
