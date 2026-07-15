---
'vaultkeeper': major
'@vaultkeeper/test-helpers': minor
---

Breaking: `VaultKeeper.setup()` now requires an explicit executable-trust choice. This is a major bump on `vaultkeeper`, authorized by the maintainer on issue #123.

`setup()` previously defaulted `executablePath` to `'dev'` when omitted, which silently skipped Trust On First Use (TOFU) executable-identity verification — so a bare `await vault.setup(name)` minted an unverified token even though the caller may have believed trust was enforced. This was a permissive security default for a secrets tool. Existing `setup(name)` calls must now pass `executablePath` (runs TOFU verification) or `skipTrust: true` (development-only opt-out); omitting both throws `ExecutableTrustRequiredError`.

`setup()` now requires the caller to make the decision explicitly. Provide exactly one of:

- `executablePath` — the calling executable's real path, which runs TOFU verification (the safe, production choice), or
- `skipTrust: true` — a self-describing, greppable, development-only opt-out that deliberately skips verification.

Supplying neither — or both — now throws the new typed `ExecutableTrustRequiredError` (a `VaultError` subclass, exported from the package root) instead of silently skipping trust. Its `reason` field is `'missing-choice'` or `'conflicting-choice'`.

Passing a real `executablePath` behaves exactly as before, including the existing `setDevelopmentMode()` allowlist bypass and `IdentityMismatchError` on a hash conflict.

**Migration** — every existing `setup()` call must now name a trust choice:

```ts
// Before — unverified by default (silent skip):
await vault.setup('MY_API_KEY')

// After — verify the calling executable (production):
await vault.setup('MY_API_KEY', { executablePath: process.argv[1] })

// After — deliberately skip verification (development/tests only):
await vault.setup('MY_API_KEY', { skipTrust: true })
```

Callers that previously passed the `'dev'` sentinel should switch to the dedicated opt-out:

```ts
// Before:
await vault.setup('MY_API_KEY', { executablePath: 'dev' })
// After:
await vault.setup('MY_API_KEY', { skipTrust: true })
```

`@vaultkeeper/test-helpers`: `TestVault` gains a `setup(name, options?)` convenience method that defaults to `skipTrust: true`, so consumer tests calling it stay hermetic without naming a real executable. Pass `executablePath` to exercise real verification instead.
