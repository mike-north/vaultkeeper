---
'vaultkeeper': patch
---

Preserve finite-use token budgets and denial records through expiry, even under capacity pressure or a backward clock adjustment. When the TypeScript authorization table is full of live entries, new finite-use authorizations fail with `AuthorizationDeniedError` until space can be reclaimed. A failed previous-key token refresh preserves the remaining budget.
