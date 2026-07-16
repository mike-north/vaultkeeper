---
'@vaultkeeper/wasm': minor
---

Enforce the `setup()` executable-trust choice at compile time in `@vaultkeeper/wasm`, matching the TypeScript `vaultkeeper` library. Versioned as a minor bump under 0.x semver (a tightened type contract is a compile break for callers omitting the choice, but ships as a minor while the SDK is pre-1.0).

Previously `setup()`'s options argument was typed as optional (`options?: SetupOptions`) with all-optional fields, so a two-argument `vault.setup(name, value)` — or `vault.setup(name, value, {})` — type-checked cleanly yet threw `ExecutableTrustRequiredError` (`reason: 'missing-choice'`) at runtime. WASM users got no compile-time protection on the very trust choice the rest of the ecosystem type-enforces.

`SetupOptions` is now `SetupOptionsBase` (`ttlMinutes` / `useLimit` / `backendType`) intersected with a discriminated union requiring **exactly one** of `executablePath` or `skipTrust: true`, and the options argument is required. As a result these are now compile errors instead of runtime-only failures:

```ts
vault.setup('MY_API_KEY', 'my-secret-value')                                  // missing choice
vault.setup('MY_API_KEY', 'my-secret-value', {})                              // missing choice
vault.setup('MY_API_KEY', 'my-secret-value', { executablePath: p, skipTrust: true }) // both
```

The valid single-choice forms are unchanged:

```ts
vault.setup('MY_API_KEY', 'my-secret-value', { executablePath: process.argv[1] })
vault.setup('MY_API_KEY', 'my-secret-value', { skipTrust: true })
```

The runtime `ExecutableTrustRequiredError` remains as a backstop for untyped (plain-JavaScript) callers.
