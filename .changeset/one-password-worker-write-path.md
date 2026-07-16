---
'vaultkeeper': minor
---

Extend the 1Password per-access worker with a `store`/`delete` write path so `--require-presence-per-use` covers writes, not just reads. Previously the per-access worker was read-only, so `OnePasswordBackend` reported `presenceEnforcedOperations: ['read']` and a flagged `store`/`delete` failed closed with `NotCapableError` — correct, but limited. Now every keyed operation (`retrieve`, `store`, `delete`) spawns its own fresh worker process forcing a distinct biometric approval, `presenceEnforcedOperations` reports `['read', 'store', 'delete']`, and the earlier `NotCapableError` refusal is replaced by the same fresh-action guarantee reads already had. The secret value for `store` is delivered to the worker over stdin — never argv — so it never appears in a process listing, shell history, or log. A declined presence action throws `PresenceDeclinedError`; a timed-out one throws `PresenceTimeoutError`.
