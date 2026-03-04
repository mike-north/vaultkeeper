---
"vaultkeeper": patch
---

Fix built-in backends not registered at module load (issue #21)

BackendRegistry shipped empty because no built-in backends called
`BackendRegistry.register()`. Adds a side-effect module
(`register-builtins.ts`) imported from the package entry point so all
six built-in backends (file, keychain, dpapi, secret-tool, 1password,
yubikey) are available immediately after `import 'vaultkeeper'`.

Also updates `BackendFactory` to accept an optional `BackendConfig`,
allowing `VaultKeeper.init()` to forward per-backend configuration
(e.g. 1Password vault ID and access mode) through the registry.
