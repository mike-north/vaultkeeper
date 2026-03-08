---
'vaultkeeper': patch
---

Doctor checks are now scoped to the backends configured in vault config. System dependency checks (`secret-tool`, `security`, `powershell`) are only treated as required when the corresponding backend is enabled, eliminating false positives on systems that use only the file backend or a subset of platform backends. Conversely, `op` and `ykman` are now treated as required when the `1password` or `yubikey` backends are explicitly enabled. When no `backends` config is provided, all platform-default checks remain required (backward-compatible behavior).
