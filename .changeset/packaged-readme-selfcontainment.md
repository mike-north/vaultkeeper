---
'vaultkeeper': patch
'@vaultkeeper/cli': patch
---

Make the packaged READMEs self-contained: `vaultkeeper` and `@vaultkeeper/cli` now include a
minimal, safe-by-default (`file` backend) example `VaultConfig`/config JSON, plus inline
explanations of key rotation grace periods and trust tiers — the concepts the CLI's own `config
show` and `exec` output surface — so the golden path no longer depends on fetching the unshipped
repository README.
