---
'vaultkeeper': patch
'@vaultkeeper/cli': patch
---

Add a supported recovery path for a corrupt or unreadable `config.json`.

- `vaultkeeper config init --force` now overwrites an existing config file, including one that's present-but-unparseable. `config init` without `--force` keeps its current non-destructive refusal, and now points at `config init --force` in its refusal message. `--force` composes with `--backend` (e.g. `config init --force --backend file`).
- `ConfigParseError` (and the other `loadConfig` errors sharing its remediation hint) now names `vaultkeeper config init --force` instead of `vaultkeeper config init` — the previous hint sent users to a command that provably failed in the exact state that produced the error.
