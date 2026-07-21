---
"vaultkeeper": patch
"@vaultkeeper/wasm": patch
---

Internal: `validateClaims`/`validate_claims` — the single validation chokepoint every token passes through, in both the TypeScript library and the Rust core — now discriminate on a claims payload's kind. An ordinary secret claim still requires a non-empty `val` and `bkd` exactly as before; a session signing-key lease (no secret value) instead requires a non-empty `kid` and a present `kgen` (never defaulted to generation 0). No public API changed — `VaultClaims` remains an internal type, and every existing secret-token code path is unchanged.
