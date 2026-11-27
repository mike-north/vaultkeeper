---
'@vaultkeeper/cli': patch
'vaultkeeper': patch
---

Preserve significant trailing characters in CLI store input and add `--raw` for final line endings. Reject whitespace-only input in both modes because secret tokens require a nonblank value.

Preserve final line endings when retrieving credentials through Secret Service.
