---
'@vaultkeeper/wasm': patch
---

Fix two trust-manifest integrity gaps in the Rust core's TOFU verify/commit split. `PendingTrust::commit` now reloads the on-disk manifest immediately before saving and re-classifies the staged `(namespace, hash)` entry against the current state: a concurrent write to a **different namespace** is preserved (previously it was silently discarded by saving the verify-time snapshot — mirrors the TypeScript SDK's fix for the same hazard), and a concurrent write of a **different hash for the same namespace** is now refused as a TOFU conflict (`IdentityMismatchError`, nothing written) instead of being silently merged in as a second approved hash.
