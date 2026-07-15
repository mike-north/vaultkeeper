---
"@vaultkeeper/wasm": patch
"vaultkeeper": patch
---

Close the `@vaultkeeper/wasm` getting-started and API-reference documentation gaps.

- The WASM quick start now leads with an ESM-setup callout. `@vaultkeeper/wasm` is ESM-only (no CommonJS fallback), so a copy-paste of the snippet into a default `npm init -y` (CommonJS) project previously failed with `SyntaxError: Cannot use import statement outside a module`. The callout documents adding `"type": "module"` first, so the documented steps now succeed from a fresh project.
- `SetupOptions.executablePath` JSDoc (and the generated API reference) now states positively that this WASM SDK records the path as a claim label and performs no trust-on-first-use (TOFU) verification — no hashing, manifest check, or throw on a changed/nonexistent path — unlike the TypeScript `vaultkeeper` library's `VaultKeeper.setup()`. Cross-references the behavioral follow-up tracked separately.
- The `vaultkeeper` README Trust-tiers section now scopes its "requires an explicit executable-trust choice / never silently skips verification" guarantee to the TypeScript library, and notes that `@vaultkeeper/wasm` records `executablePath` as a claim label without running TOFU verification.
- `SetupOptions.backendType` is now documented as a claim label only (recorded in the token's `bkd` claim) that does not select or route through a functional backend, mirroring the claim-label framing of `executablePath`.
