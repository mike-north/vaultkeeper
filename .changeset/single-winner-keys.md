---
'vaultkeeper': patch
'@vaultkeeper/wasm': patch
---

Keep the first published wrapping key, file-store master key, and token state when multiple vaults initialize concurrently. Diagnose missing key material on read without generating a replacement.

Preserve owner access under restrictive umasks in the native and WASM hosts, and accept cross-realm byte arrays in the WASM host bridge.
