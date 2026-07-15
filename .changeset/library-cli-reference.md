---
'vaultkeeper': patch
---

Fix library error messages and public JSDoc that instructed users to run a bare `vaultkeeper config init` as if the CLI shipped with the `vaultkeeper` package. The library has no `bin` — the CLI ships separately as `@vaultkeeper/cli`. Remediation text in `ConfigParseError`, `ConfigValidationError`, `FilesystemError` (via `loadConfig`), and JSDoc on `defaultBackendType`, `platformNativeBackendType`, `loadConfig`, and `VaultKeeperOptions` now name `@vaultkeeper/cli` explicitly, or point to the JS-API alternative of repairing/replacing the config directly (via `config`/`configDir`). The README now states near the top that the CLI ships separately.
