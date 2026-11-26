---
'vaultkeeper': patch
---

Prevent deleting a current file-backed credential from exposing its retired legacy value.
Preserve a replacement stored after a legacy-only credential has been deleted.
