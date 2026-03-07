---
"@vaultkeeper/cli": patch
---

Add `--skip-doctor` flag and `VAULTKEEPER_SKIP_DOCTOR=1` environment variable to CLI commands that initialize VaultKeeper. When set, preflight dependency checks are skipped — useful on systems where the native credential store is unavailable but the `file` backend is configured.
