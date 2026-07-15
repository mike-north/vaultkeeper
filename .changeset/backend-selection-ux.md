---
'vaultkeeper': minor
'@vaultkeeper/cli': minor
---

Make backend selection visible and overridable from the CLI and introspectable from the library.

- `vaultkeeper config init --backend <type>` now writes a config whose first enabled backend is `<type>`. Valid values are the registered backend types; an unknown value exits 2 and lists the valid types.
- Any unknown flag on a `config` subcommand (`config init`, `config show`) now exits 2 with an "unknown option" error instead of being silently ignored — a typo can no longer send secrets to an unintended credential store.
- `config init` output now states which backend was configured and how to change it. `config show` reports the resolved active backend (first enabled).
- New public `platformNativeBackendType()` reports the OS-native credential store for the current platform (`keychain` on macOS, `dpapi` on Windows, `file` elsewhere) — the store you can opt into with `--backend`.
- New public `VaultKeeper.activeBackendType` getter exposes the type of the active (first enabled) backend at runtime.
