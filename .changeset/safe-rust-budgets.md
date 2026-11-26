---
'@vaultkeeper/wasm': patch
---

Preserve finite-use authorization budgets through expiry under capacity pressure, including signing leases. New finite-use authorizations fail closed when all accounting slots are live.

Scrub the decrypted secret value when authorization is refused, including when a retained finite-use budget is exhausted or the accounting table is full.

JWE expiry continues to advance after backward wall-clock adjustments, and issued handles honor the same cutoff as redemption.
