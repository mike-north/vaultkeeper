---
'@vaultkeeper/wasm': patch
---

On Unix, the Node/WASM SDK and native CLI apply and verify owner-only permissions before writing persistent key bytes, then atomically publish the completed file. On macOS, new key files are created without inheriting ACL grants from the storage directory. A failed write preserves the previous file. Readers holding an older permissive file descriptor can only see its original bytes.
