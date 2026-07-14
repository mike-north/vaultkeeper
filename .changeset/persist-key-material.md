---
'vaultkeeper': minor
'@vaultkeeper/cli': patch
---

Persist key material across processes so cached tokens and the rotation grace period work between CLI invocations.

- `KeyManager` encryption keys are now persisted under the config directory, encrypted at rest with AES-256-GCM under an owner-only (`0600`) wrapping key — reusing the same authenticated-cipher primitives as the file backend. Persistence is active only when `VaultKeeper` loads its configuration from disk (no injected `config`/`backend`); instances built with an injected `config` or `backend` keep keys in memory, so tests and embedders stay hermetic.
- A JWE minted by one process is now authorizable by a later process within its validity window: its `kid` still resolves after the minting process exits. Previously every process generated fresh keys, so a cached token always failed with `KeyRevokedError`.
- `vaultkeeper exec --cache` now genuinely reuses a cached token on a second run by the same trusted caller — without re-minting and without the misleading "Cached token expired" message. Cached tokens are reusable until they expire (the secret's TTL) or the key is rotated/revoked, after which `exec` transparently mints a fresh one.
- The cached-token path no longer collapses every authorization failure into a generic "expired" message. Each failure now surfaces its actual cause (e.g. `KeyRevokedError`, `TokenExpiredError`).
- The rotation grace-period guard now survives across processes: running `rotate-key` twice while the previous key is still in its grace period fails the second time with `RotationInProgressError` (non-zero exit) instead of silently rotating again.
