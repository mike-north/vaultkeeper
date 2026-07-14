---
'vaultkeeper': minor
'@vaultkeeper/cli': minor
---

`doctor` and `config show` now detect an invalid config file instead of silently ignoring it. `doctor` validates the config file (when present) as part of its preflight checks and reports a failing `config` check with the parse/validation error and file path, exiting non-zero. `config show` on invalid JSON now exits non-zero with the parse error (including a line/column location when available) instead of dumping the raw file with exit 0. Every config parse/validation error raised by `loadConfig()` — surfaced through `store`, `delete`, `exec`, `config show`, and `doctor` alike — now includes the config file path, the parse location where available, and a remediation hint naming `vaultkeeper config init`.

`loadConfig()` now falls back to platform defaults only when the config file is missing (`ENOENT`). A present-but-unreadable file (e.g. a permissions error) is rethrown as a typed `FilesystemError` instead of being silently treated as "no config" — a genuinely broken config was previously invisible to `doctor` and `config show`.

The "no config file" story is now uniform across `store`, `delete`, `exec`, `config show`, and `doctor`: each falls back to platform defaults and prints a one-line notice naming the resolved backend and `vaultkeeper config init` (e.g. `No config file found; using platform defaults (keychain). Run 'vaultkeeper config init' to persist one.`). Previously `config show` errored with exit 1 on a missing config file while the other commands defaulted silently; `config show` now defaults and reports it like the rest.

New public `ConfigParseError` (with `path` and `location` fields) is thrown on invalid config JSON. `ConfigValidationError` gains an optional `configFilePath` field. `PreflightCheckStatus` gains an `'invalid'` value, and `RunDoctorOptions` gains an optional `configDir` field that lets `runDoctor`/`VaultKeeper.doctor()` load and validate the config itself.
