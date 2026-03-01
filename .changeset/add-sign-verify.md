---
"vaultkeeper": minor
---

Add delegated signing, static verification, and backend setup protocol to VaultKeeper.

**Signing & Verification:**
`VaultKeeper.sign()` signs arbitrary data using a private key stored in the vault, returning a base64-encoded signature without exposing the key to the caller. `VaultKeeper.verify()` is a static method that verifies a signature against a public key and requires no VaultKeeper instance. New exported types: `SignRequest`, `SignResult`, `VerifyRequest`. New error: `InvalidAlgorithmError` for disallowed algorithm overrides.

**Backend Setup Protocol:**
Adds an async-generator-based interactive setup protocol for backend configuration. Each backend that requires user input implements a setup generator that yields `SetupQuestion` objects; consumers render them and send answers back via `generator.next(answer)`. Includes discovery modules for 1Password, macOS Keychain, and YubiKey. New exported types: `SetupQuestion`, `SetupChoice`, `SetupResult`, `BackendSetupFactory`. New `BackendRegistry` methods: `registerSetup()`, `getSetup()`, `hasSetup()`. `BackendConfig` gains an `options` field for persisting setup results.
