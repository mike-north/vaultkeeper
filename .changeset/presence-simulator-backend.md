---
"@vaultkeeper/test-helpers": minor
"vaultkeeper": minor
---

Add `PresenceSimulatorBackend` to `@vaultkeeper/test-helpers`: a test-only backend that scripts vaultkeeper's presence signal (including its absence) so a consumer can prove in CI that an automation signer attempting a presence-gated operation is refused. Per-operation outcomes are scriptable across `'grant'` / `'refuse'` / `'timeout'` / `'not-capable'` via `forTesting({ operations })`, or armed one call at a time via `armPresence` to prove presence is demanded fresh on every call. Three stacked guards keep it unreachable from production: it is never registered with the backend registry, has no default constructor, and its `forTesting()` factory throws a new `TestDoubleMisuseError` (exported from `vaultkeeper`) when `NODE_ENV` is `'production'`.
