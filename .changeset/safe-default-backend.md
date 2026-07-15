---
'vaultkeeper': minor
'@vaultkeeper/cli': minor
---

Make the zero-config default backend safe: the shortest documented getting-started path can no longer silently write a secret to your real OS credential store.

- With no config file present, a bare `VaultKeeper.init()` — and `vaultkeeper config init` with no `--backend` — now resolves to the portable, self-contained `file` backend on **every** platform, including macOS and Windows. Previously it targeted the OS-native credential store (macOS Keychain, Windows DPAPI), so copy-pasting the first documented example could store a secret in the real login keychain before the user knew backends existed.
- The platform-native store stays fully supported as an explicit opt-in: `vaultkeeper config init --backend keychain` / `--backend dpapi`, or an explicit config.
- New public `defaultBackendType()` returns the zero-config default (`'file'`) on every platform. The former `platformDefaultBackendType()` is renamed to `platformNativeBackendType()` — it never was the zero-config default and now reads as what it is: the OS-native store you can opt into.
- The `doctor` / `store` (and `delete` / `exec` / `config show`) "no config file" advisory now names the `file` default and spells out the remediation as `vaultkeeper config init --backend file`, never a bare `config init`, so following the hint verbatim persists exactly the backend that was in effect.

Note: this changes only the TypeScript library and Node.js CLI. The native Rust CLI's zero-config default is unchanged for now.
