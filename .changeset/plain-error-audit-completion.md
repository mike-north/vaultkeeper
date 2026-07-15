---
'vaultkeeper': patch
'@vaultkeeper/cli': patch
---

Complete the plain-`Error` audit (issues #115/#126 covered `config.ts` and the file backend): every remaining `throw new Error(...)` in product source now throws a typed error instead.

- `vaultkeeper`: `util/at-rest.ts` and `backend/yubikey-backend.ts`'s encrypted-envelope decoding now throw `DecryptionError` (malformed envelope, unsupported/legacy file version, or a failed AES-GCM auth tag check) instead of a plain `Error`. `util/platform.ts`'s `currentPlatform()`, `backend/one-password-constants.ts`'s `getIntegrationVersion()`, and `yubikey-backend.ts`'s YubiKey HMAC response validation now throw `SetupError`. `util/exec.ts`'s `execCommand`/`execCommandFull` and the YubiKey `ykman` challenge-response call now throw `ExecError`. `OnePasswordBackend`'s constructor validation (mutually exclusive `accessMode`/`serviceAccountToken`/`account` options) now throws `ConfigValidationError`, and its per-access worker crash/spawn-failure paths now throw `BackendUnavailableError`. No new public error classes or fields were added — every site reuses an existing `VaultError` subclass.
- `@vaultkeeper/cli`: the non-interactive-approval-required error (in both `approval.ts`'s `promptApproval` and `commands/exec.ts`'s trust gate) now throws a new internal `NonInteractiveApprovalError` (not part of the public API, matching the existing internal `ConfigDirFlagError` pattern) instead of a plain `Error`.

A new repo-wide guard test (`no-plain-error.test.ts` in both packages) scans every source file under `src/` and fails if a plain `Error` construction (`throw`/`reject`) reappears.
