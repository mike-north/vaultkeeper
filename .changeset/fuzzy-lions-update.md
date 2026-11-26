---
'vaultkeeper': patch
---

Preserve the prior macOS Keychain credential when a replacement is rejected. Keychain writes send the credential over stdin and reject IDs with line breaks or commands that exceed the security CLI's input limit.
