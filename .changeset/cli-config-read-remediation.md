---
'@vaultkeeper/cli': patch
---

Fix two CLI config-error remediation gaps left over from #129:

- An unreadable `config.json` (e.g. `EACCES`/`EPERM` from a root-owned file or `chmod 000`) now gets a CLI-native message naming the file path and suggesting a permissions check — it no longer falls through to the library's "install `@vaultkeeper/cli`" text, and it never recommends `config init --force` (which would hit the same permission error trying to write the replacement file).
- A structurally invalid `config.json` now names the failing field again (e.g. `` The config at `<path>` is invalid (`version`) — run `vaultkeeper config init --force` to overwrite it. ``) — #129 dropped this detail with no replacement.
