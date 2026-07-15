---
'@vaultkeeper/wasm': minor
---

Fix the WASM SDK's JS host bridge erasing filesystem errno codes: a permission-denied read or delete previously surfaced as a generic `VaultError`, indistinguishable from any other failure, instead of a typed error a caller could branch on.

`readFile`/`deleteFile`/`fileExists` in the Node host bridge (`createNodeHost`) now reject with a structured `{ message, path, code }` contract that `JsHostPlatform` (the Rust side of the bridge) reads back to build a typed `VaultError::Filesystem`, mirroring the native CLI host's classification: a genuine "does not exist" still resolves to `SecretNotFoundError`, while permission and other errno failures now surface as a new public `FilesystemError` (with `path`, `permission`, and `code` fields — `code` carries the underlying errno, e.g. `EACCES`, when available). Exported from `@vaultkeeper/wasm` alongside the rest of the typed error hierarchy.
