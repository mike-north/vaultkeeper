---
"@vaultkeeper/wasm": patch
---

Complete the `VaultError` taxonomy so it can bridge losslessly to `@vaultkeeper/wasm`. The Rust core gains 14 new `VaultError` variants (`NotCapable`, `PresenceDeclined`, `PresenceTimeout`, `InvalidKeyMaterial`, `SigningKeyNotFound`, `SigningKeyAlreadyExists`, `SigningNotSupported`, `Exec`, `Fetch`, `InvalidToken`, `AccessorConsumed`, `ConfigValidation`, `UnknownBackendType`, `ConfigParse`) with machine-readable context fields matching the pure-TypeScript `vaultkeeper` library's error classes.

`@vaultkeeper/wasm` now exports the matching typed error classes — `NotCapableError`, `PresenceDeclinedError`, `PresenceTimeoutError`, `InvalidKeyMaterialError`, `SigningKeyNotFoundError`, `SigningKeyAlreadyExistsError`, `SigningNotSupportedError`, `ExecError`, `FetchError`, `ConfigValidationError`, `UnknownBackendTypeError`, `ConfigParseError` — plus `BackendLockedError`, `DeviceNotPresentError`, `AuthorizationDeniedError`, `BackendUnavailableError`, `PluginNotFoundError`, `InvalidAlgorithmError`, and `SetupError`, which had Rust-side variants already but were never reconstructed at the WASM boundary and previously collapsed to the generic `VaultError` base class.

The error-code table that drives the boundary (`vaultErrorCode`) is now a single source of truth shared by the Rust match (`vault_error_code`/`vault_error_fields` in `vaultkeeper-core`) and the TypeScript reconstruction map (`ALL_VAULT_ERROR_CODES` in `@vaultkeeper/wasm`'s `errors.ts`), with a parity test asserting both sides list exactly the same codes and that every code round-trips to the correct typed subclass with the correct field values. No existing error path changed behavior.
