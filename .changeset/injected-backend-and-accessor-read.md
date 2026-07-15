---
'vaultkeeper': minor
---

Fix two library rough edges surfaced by the direct-integration path.

- `VaultKeeper.activeBackendType` no longer throws `BackendUnavailableError` when a backend was injected via `init({ backend })`. It now reports the injected backend's declared `type` (or the stable `'custom'` sentinel if it declares an empty type). The config-driven path is unchanged.
- `SecretAccessor.read()` now passes the callback's return value through: `read<T>(cb: (buf: Buffer) => T): T`, so `const value = accessor.read((buf) => buf.toString('utf8'))` yields the derived value instead of `undefined`. The buffer is still zeroed after the callback returns, so returning the raw buffer only ever yields zeroed bytes — derive a value inside the callback.
