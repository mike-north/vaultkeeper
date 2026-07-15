---
'vaultkeeper': patch
'@vaultkeeper/cli': patch
---

Make the packaged READMEs self-contained: `vaultkeeper` and `@vaultkeeper/cli` now include a
minimal, safe-by-default (`file` backend) example `VaultConfig`/config JSON, plus inline
explanations of key rotation grace periods, the `trustTier` policy label, and the
trust-on-first-use (TOFU) check that `exec` reports on every run — so the golden path no longer
depends on fetching the unshipped repository README.
