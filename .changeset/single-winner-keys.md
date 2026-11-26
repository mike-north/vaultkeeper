---
'vaultkeeper': patch
'@vaultkeeper/wasm': patch
---

Keep the first published wrapping key, file-store master key, and token state when multiple vaults initialize concurrently. Diagnose missing key material on read without generating a replacement.
