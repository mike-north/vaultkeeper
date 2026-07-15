---
'vaultkeeper': minor
'@vaultkeeper/cli': patch
---

Fix `dev-mode` invalid-action misdiagnosis and audit `config.ts`/the file backend for plain `Error` throws.

- `vaultkeeper dev-mode <action> --script <path>` now distinguishes an invalid action from missing args: an unrecognized action (e.g. `banana`) emits `unknown action "<x>" (expected "enable" or "disable")` (exit 2), while `missing action or --script flag` is reserved for genuinely absent arguments.
- The encrypted-file secret backend (`FileBackend`) now surfaces `EACCES`/permission failures reading, writing, or deleting a secret entry as a typed `FilesystemError` instead of the raw Node.js error.
- Added a new `DecryptionError` (extends `VaultError`) for when a stored secret entry fails to decrypt (corrupted ciphertext or a failed AES-GCM auth tag check) — previously thrown as a plain `Error`.
