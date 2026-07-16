---
'@vaultkeeper/wasm': patch
---

Fix a trust-manifest integrity gap in the Rust core's TOFU verify/commit split: `PendingTrust::commit` reloads the on-disk manifest immediately before saving and merges in only the staged `(namespace, hash)` entry, instead of persisting the whole-manifest snapshot captured back at verify time. Previously, a concurrent process's write to a different namespace between verify and commit was silently discarded. Mirrors the TypeScript SDK's fix for the same hazard.
