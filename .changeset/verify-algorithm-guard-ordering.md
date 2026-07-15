---
'vaultkeeper': patch
---

Validate the signing/verification algorithm before parsing key material in `VaultKeeper.verify()` (and the internal signing path). A disallowed algorithm (e.g. `md5`) now throws `InvalidAlgorithmError` unconditionally and synchronously, as documented — even when the supplied key material is also malformed. Previously a malformed public key short-circuited to `false` and silently skipped the algorithm guard, so callers relying on `try`/`catch` for `InvalidAlgorithmError` were not protected when key material was attacker-controlled.
