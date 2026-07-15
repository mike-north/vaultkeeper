---
'vaultkeeper': patch
'@vaultkeeper/cli': patch
'@vaultkeeper/test-helpers': patch
---

Round out the shipped package docs so a reader offline (registry-only, air-gapped) can find everything without the GitHub URL:

- `vaultkeeper` README: new "Multiple secrets in one request" section documenting `SecretTokenMap` and the `{{secret:name}}` placeholder for injecting several secrets into one `fetch()`/`exec()` call; a runnable inline `exec()` example (secret injected via `env`); a complete error-types table covering all `VaultError` subclasses; a full `VaultConfig`/`BackendConfig` field reference; and a "Doctor / preflight checks" section explaining required-vs-informational checks and that a plugin checkmark means "binary detected on PATH", not "backend active".
- `vaultkeeper` README: `verify()` now notes that the disallowed-algorithm throw does not apply to Ed25519/Ed448 keys (the algorithm override is ignored). The "Testing against this library" section notes `@vaultkeeper/test-helpers` belongs in `devDependencies` and warns that the real `VaultKeeper.setup()` always requires `executablePath` or `skipTrust`.
- `@vaultkeeper/test-helpers` README: strengthened the warning that the test-only zero-arg `setup()` default does not carry over to the real `VaultKeeper.setup()`.
- `@vaultkeeper/cli` README: new "Doctor / preflight checks" section on checkmark semantics — plugin checks (`op`/`ykman`) are informational when their backend isn't enabled, but enabling the `1password`/`yubikey` backend promotes its tool check to required; points at the now-self-contained library README for the full error hierarchy and config reference.
