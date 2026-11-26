---
'vaultkeeper': patch
---

Preserve the prior macOS Keychain credential when a replacement is rejected. Replace credentials only in their owning keychain, so an unavailable keychain cannot cause a second copy in the default keychain. Send credentials over stdin and reject IDs containing a line break or NUL. New items must fit the security CLI's input limit.
