---
"vaultkeeper": minor
"@vaultkeeper/test-helpers": minor
---

Add `ListableBackend` interface with `list()` method for enumerating stored secrets, implemented on all backends. Add `isListableBackend()` type guard. `InMemoryBackend` now also implements `ListableBackend`.
