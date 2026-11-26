---
'vaultkeeper': patch
---

Make delegated fetch reject HTTP redirects with `FetchError`. This keeps delegated credentials from being forwarded to a redirect destination or disclosed through redirect response metadata.
