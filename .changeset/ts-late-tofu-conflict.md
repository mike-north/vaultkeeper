---
'vaultkeeper': patch
---

Fix a late TOFU conflict window in `commitTrust`: if another process recorded a _different_ executable hash for the same trust-manifest namespace between the verify and commit phases, `commitTrust` reloaded the manifest but then unconditionally merged the staged hash in — silently approving a second hash for that namespace and bypassing the TOFU-conflict record-nothing rule. `commitTrust` now re-classifies the staged entry against the freshly reloaded manifest: an already-trusted hash stays a no-op, an empty namespace still merges, but a namespace whose approved hashes don't include the staged one now throws `IdentityMismatchError` and writes nothing. Mirrors the Rust `PendingTrust::commit` fix.
