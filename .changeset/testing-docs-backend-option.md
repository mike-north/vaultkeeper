---
'vaultkeeper': minor
---

Add a `backend` option to `VaultKeeperOptions` that accepts a `SecretBackend` instance directly, so tests and embedders can inject a backend without registering it globally via `BackendRegistry` or hand-assembling a full `VaultConfig`. When `backend` is set it always takes precedence over the backend that `config.backends` (or the config loaded from `configDir`) would otherwise resolve; other config fields still come from `config`/`configDir` when supplied, and a minimal built-in default config is used automatically when `config` is omitted. The README's "Testing your own code" and "Injecting a backend directly" sections document a dependency-injection pattern for testing code that uses `VaultKeeper`.
