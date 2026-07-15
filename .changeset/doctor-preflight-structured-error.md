---
'vaultkeeper': minor
'@vaultkeeper/cli': patch
---

Give the doctor `config` preflight check structured error context so the CLI can render a CLI-native remediation instead of the library's install text.

- The public `PreflightCheck` shape gains an optional `error` field (`PreflightCheckError`: `kind` + `configPath` + optional parse `location`) carrying remediation-free, machine-readable context when the `config` check fails on a present-but-invalid config file. A consumer can build its own audience-appropriate remediation from these fields instead of parsing the human-readable `reason` prose.
- `vaultkeeper doctor` run against a corrupt or invalid config now shows the CLI-native remediation (config path + `vaultkeeper config init --force`), wording-consistent with every other command, and no longer tells a user already running the CLI to "install @vaultkeeper/cli". The library's own `reason` text is unchanged for library consumers.
