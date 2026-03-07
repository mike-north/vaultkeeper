---
"vaultkeeper": patch
"@vaultkeeper/test-helpers": patch
---

Fix error type correctness: `InMemoryBackend` now throws `SecretNotFoundError` (not plain `Error`), exceeding a token's use limit throws `UsageLimitExceededError` (not `TokenRevokedError`), and double-reading a `SecretAccessor` throws a descriptive error instead of a raw Proxy `TypeError`.
