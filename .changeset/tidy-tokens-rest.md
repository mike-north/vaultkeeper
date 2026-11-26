---
'@vaultkeeper/wasm': patch
---

Enforce finite-use token budgets across restarted and concurrent native CLI invocations. Order usage commits against native key rotation and revocation, and refuse queued launches without spending a use if their token's key was revoked while waiting.

Clear transient plaintext key-state buffers after loading persisted keys.
