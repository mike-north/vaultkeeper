---
'vaultkeeper': patch
---

Keep substituted credentials out of delegated fetch response metadata. The response and its clones omit the transport URL, headers, and reason phrase while preserving the body stream, numeric status, and redirect flag.
