---
'vaultkeeper': patch
'@vaultkeeper/wasm': patch
---

Publish file-backed signing identities atomically without replacing an existing key. Concurrent first-time writers reuse the wrapping key selected by the filesystem, and a later writer can complete an interrupted wrapping-key repair using the selected key.

Ordinary storage continues to work on filesystems without hard links. The TypeScript SDK can initialize and repair wrapping keys in macOS config directories up to the 1,009-byte limit supported by key-state persistence. TypeScript, native Rust, and WASM use the same repair filename for shared wrapping keys.
