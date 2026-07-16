---
'vaultkeeper': patch
---

Fix `VaultKeeper.setup()` recording TOFU (trust-on-first-use) trust for an executable before confirming the secret actually exists.

`#resolveExecutableIdentity` ran trust verification — which durably records a first-encounter or Sigstore hash in the trust manifest — before `backend.retrieve()`. A `setup()` call for a nonexistent secret therefore still left the caller's hash permanently approved, letting an attacker (or a typo'd script) pre-seed TOFU trust without ever completing a legitimate first encounter; a later, real first encounter would then silently match the pre-seeded hash instead of being verified as new.

Trust verification is now split into a verify phase (computes the hash and classifies it against the manifest, staging but not writing any first-encounter/Sigstore update) and a commit phase that only runs after `setup()`'s secret retrieval and token minting succeed. Shape validation (missing/conflicting/legacy-`'dev'`-sentinel trust choices) still fails fast before any backend read, and a TOFU hash conflict still fails without ever recording the new hash — only the successful first-encounter write is deferred.
