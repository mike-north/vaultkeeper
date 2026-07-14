---
'vaultkeeper': minor
'@vaultkeeper/cli': patch
---

Make the CLI's trust-on-first-use (TOFU) model functional. `vaultkeeper approve --script <path>` now computes the script's SHA-256 and records it in the trust manifest (idempotently), and `vaultkeeper exec` consults the manifest before prompting: a caller whose current hash is already approved runs without an interactive prompt and reports a verified trust state, while a modified or unapproved caller is treated as untrusted. The library gains two public methods on `VaultKeeper` — `approveExecutable()` and `checkExecutableTrust()` — plus the `ExecutableTrustStatus` type, which back this behavior.
