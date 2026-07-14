---
"vaultkeeper": patch
"@vaultkeeper/cli": patch
---

Honor `BackendConfig.path` for file-based backends. Previously the documented `path` option was validated and then silently ignored: secrets always landed in the hardcoded `$HOME/.vaultkeeper/<backend>` location. The `file`, `dpapi`, and `yubikey` backends now store, retrieve, and delete secrets under the configured directory (created on demand) when `path` is set, falling back to the default location when it is not. The CLI `store` and `delete` commands inherit the fix by routing through `VaultKeeper`, which resolves the first enabled backend from config and forwards that backend's configuration.
