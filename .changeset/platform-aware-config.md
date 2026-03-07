---
"@vaultkeeper/cli": patch
---

Fix `config init` to generate platform-appropriate defaults: `keychain` on macOS, `dpapi` on Windows, `file` on Linux. Previously always defaulted to `keychain` which is macOS-only.
