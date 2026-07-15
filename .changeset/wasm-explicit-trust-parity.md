---
'@vaultkeeper/wasm': minor
---

Breaking (0.x): `@vaultkeeper/wasm`'s `setup()` now requires an explicit executable-trust choice, closing a security-parity gap with the TypeScript `vaultkeeper` library. Versioned as a minor bump under 0.x semver (breaking changes ship as minor bumps while the SDK is pre-1.0).

Previously the WASM SDK's `setup()` defaulted the executable identity to the `'dev'` sentinel when `executablePath` was omitted, so a bare `vault.setup(name, value)` silently minted an unverified token — the same permissive default that `VaultKeeper.setup()` in the pure-TypeScript library retired. The two SDKs now share the same explicit-choice contract.

Callers must now provide exactly one of:

- `executablePath` — the calling executable's real path, bound into the minted token, or
- `skipTrust: true` — a self-describing, greppable, development-only opt-out that deliberately skips the binding.

Supplying neither — or both — or the retired `'dev'` sentinel as `executablePath` now throws the new typed `ExecutableTrustRequiredError` (a `VaultError` subclass, exported from the package root) instead of silently minting an unverified token. Its `reason` field is `'missing-choice'`, `'conflicting-choice'`, or `'legacy-dev-sentinel'`, matching the library's `ExecutableTrustRequiredError`.

**Migration** — every existing `setup()` call must now name a trust choice:

```ts
// Before — unverified by default (silent skip):
vault.setup('MY_API_KEY', 'my-secret-value')

// After — bind the calling executable (production):
vault.setup('MY_API_KEY', 'my-secret-value', { executablePath: process.argv[1] })

// After — deliberately skip the binding (development/tests only):
vault.setup('MY_API_KEY', 'my-secret-value', { skipTrust: true })
```

Callers that passed the `'dev'` sentinel as `executablePath` must switch to `skipTrust: true`; the legacy sentinel is now rejected at runtime with `ExecutableTrustRequiredError` (`reason: 'legacy-dev-sentinel'`).
