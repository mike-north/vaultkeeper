---
'vaultkeeper': patch
---

Enforce the original JWE expiry when a TypeScript capability is used. Direct reads and delegated fetch or exec reject expired capabilities, including when the earliest lease in a named operation expires during request preparation. `sign()` rejects secret capabilities with `AuthorizationDeniedError` regardless of expiry. Delegated fetch continues to report an unavailable fetch implementation as a `FetchError`.
