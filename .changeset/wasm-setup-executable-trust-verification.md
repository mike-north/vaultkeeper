---
'@vaultkeeper/wasm': minor
---

Enforce executable-trust verification in `setup()` when an `executablePath` is supplied.

Previously, passing `executablePath` bound the raw path into the token's `exe` claim with no hashing and no trust-manifest consultation — a caller that explicitly asked for executable trust got none. `setup()` now hashes the executable and runs trust-on-first-use verification (Sigstore → trust-manifest match → TOFU first-encounter) through the host bridge, binding the verified hash into the `exe` claim, matching the pure-TypeScript `vaultkeeper` library's behavior.

- A first encounter records the executable's hash under trust-on-first-use. A later `setup()` with a matching hash passes; a changed hash throws the new `IdentityMismatchError` (carrying `previousHash` / `currentHash`) rather than silently re-approving.
- The first-encounter manifest write is committed only after the token has minted, so a failed `setup()` never leaves a premature trust record behind.
- `skipTrust: true` is unchanged — it still opts out of verification and mints a `'dev'`-bound token.

**Behavior change:** `setup()` is now `async` and returns `Promise<string>` (it performs executable hashing and manifest I/O). Callers must `await` it. Supplying `executablePath` now performs real verification and can throw `IdentityMismatchError`.
