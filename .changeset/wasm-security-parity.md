---
"@vaultkeeper/wasm": minor
---

Stop `authorize()` from returning the raw secret and add typed errors.

`authorize()` no longer exposes the plaintext secret on its result: the returned
`claims` no longer carry `val`. The secret is now read through a one-time
`SecretAccessor` on `result.secret` (`secret.read((value) => ...)`), mirroring the
`createSecretAccessor` pattern in the TypeScript library — the value is available
exactly once and is never part of the default return shape.

The SDK now exports a typed error hierarchy aligned with `VaultError`
(`SecretNotFoundError`, `InvalidTokenError`, `TokenExpiredError`, `KeyRotatedError`,
`KeyRevokedError`, `TokenRevokedError`, `UsageLimitExceededError`,
`RotationInProgressError`, `AccessorConsumedError`), and thrown errors are real
instances of these classes so `err instanceof VaultError` holds across the ecosystem.

This is a breaking change to the `authorize()` return shape: code that read
`result.claims.val` must switch to `result.secret.read(...)`.
