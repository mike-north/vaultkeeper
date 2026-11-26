---
'@vaultkeeper/wasm': patch
---

On Unix, the Node/WASM SDK and native CLI apply and verify owner-only permissions before writing persistent key bytes, then atomically publish the completed file. On macOS, new key files are created without inheriting ACL grants from the storage directory. A failed write preserves the previous file. Readers holding an older permissive file descriptor can only see its original bytes.

With Node's permission model enabled, the SDK can apply the required mode through the vault's filesystem write grant when Node disables descriptor-based `chmod`. On macOS, writing still requires the child-process grant for ACL removal.
