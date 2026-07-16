---
'vaultkeeper': patch
---

Fix the README "Multiple secrets in one request" example so it runs verbatim. It
authorized `API_KEY` and `DB_PASSWORD` without storing them first, so a
copy-pasted run threw `SecretNotFoundError` before reaching the network. The
example is now self-contained (imports `VaultKeeper`, initializes, and stores
each secret) and is executed against the built package in CI — not just
type-checked — so a runtime-throwing example fails the build.
