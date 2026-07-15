---
'@vaultkeeper/cli': patch
---

Fixed the CLI printing the library's "install @vaultkeeper/cli" remediation when it hit an invalid config (`ConfigParseError`/`ConfigValidationError`) — a user already running this CLI was told to install a CLI they already had. The CLI now prints its own remediation naming the file path and the actual recovery command: "The config at `<path>` is invalid — run `vaultkeeper config init --force` to overwrite it." The library's own message (used by JS-API consumers) is unchanged.
