---
"vaultkeeper": patch
---

Fix YubiKey backend encryption: replace AES-256-CBC (openssl CLI) with AES-256-GCM (Node.js crypto) per project security policy. Legacy CBC-encrypted files are detected with a clear migration error.
