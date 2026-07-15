---
'vaultkeeper': patch
---

Fix the `file` backend's default storage directory diverging from the resolved config directory. With no explicit `path` configured, secrets now land under `<configDir>/file/` — the same resolved config directory (honoring `--config-dir`/`VAULTKEEPER_CONFIG_DIR`, `~/.config/vaultkeeper` by default) that already holds `config.json` and key material — instead of the hardcoded `$HOME/.vaultkeeper/file`. An explicit `path` on the backend config still overrides this default unchanged.

Back-compat: `retrieve`/`exists`/`delete`/`list` transparently fall back to the old `$HOME/.vaultkeeper/file` location when a secret isn't found under the new default, so secrets stored before this change remain reachable. `store` always writes to the new location going forward — nothing at the old location is migrated automatically.
