---
'@vaultkeeper/wasm': patch
---

Fix the Rust core's file backend collapsing distinct failure modes into wrong or unstructured errors:

- `retrieve()` no longer misreports a read failure on an entry that actually exists (e.g. a permission error) as `SecretNotFoundError`. Only a genuine "entry does not exist" maps to `SecretNotFoundError`; other read failures now propagate with their real message instead of the misleading "secret not found".
- `delete()` no longer collapses a non-not-found delete failure into an opaquely re-wrapped message.
- Corrupted ciphertext or a failed AES-GCM auth tag on `retrieve()` now throws a new typed `DecryptionError` (with a `path` field), mirroring the `vaultkeeper` library's `DecryptionError`, instead of the untyped catch-all error.
