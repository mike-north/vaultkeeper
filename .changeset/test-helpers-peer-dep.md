---
"@vaultkeeper/test-helpers": minor
---

Add `store()` and `delete()` convenience methods to `TestVault`. Moves `vaultkeeper` from `dependencies` to `peerDependencies` to fix a dual-package hazard that caused `instanceof` checks on `VaultError` subclasses to fail in some consumer setups. Consumers must now list `vaultkeeper` as a direct dependency.
