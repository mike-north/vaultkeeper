---
'vaultkeeper': patch
---

Preserve the prior macOS Keychain credential when a replacement is rejected. Replace credentials only in their owning keychain and confirm absence across the search list before creating an item. Send credentials over stdin. New items require an ID without line breaks or NUL and must fit the security CLI's input limit. Existing IDs with line breaks or longer than that input limit can still be rotated.
