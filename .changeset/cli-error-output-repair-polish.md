---
'vaultkeeper': minor
'@vaultkeeper/cli': patch
---

Fixed CLI error output so recovery hints repair the file they diagnose and read cleanly.

- The invalid-config recovery hint now carries an explicit `--config-dir '<dir>'` whenever a non-default config directory is active (from `--config-dir` or `VAULTKEEPER_CONFIG_DIR`), so the copy-pasted `vaultkeeper config init --force …` command repairs the exact diagnosed file instead of writing a fresh config to the platform default and leaving the corrupt file untouched. The default-directory case stays bare (no path is leaked). A new `getPlatformDefaultConfigDir()` export computes the machine default independent of `VAULTKEEPER_CONFIG_DIR`, so a directory that came only from the environment variable still gets an explicit flag (a fresh shell running the pasted command won't have that variable set); `getDefaultConfigDir()` now delegates to it.
- `FilesystemError` now renders a human message from its typed `path`/`permission` fields — plainly stating whether the file is missing or permission-denied, with a suggested next step — instead of leaking the raw Node `ENOENT: … open '<path>'` text. The typed class and its fields are unchanged.
- `doctor` prints the config remediation exactly once (under "Next steps") instead of duplicating it inline on the failing config check.
