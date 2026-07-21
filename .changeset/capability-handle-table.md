---
'@vaultkeeper/wasm': minor
---

Additive handle-based capability surface for the `authorize()` result (issue #241): `WasmAuthorization` gains a `handleId` getter exposing the underlying core capability handle id, and `WasmVaultKeeper` gains `resolveSecretClaims(handleId)` and `releaseHandle(handleId)`.

`authorize()`'s existing public shape (`claims`, `response`, `secretAvailable`, `readSecret()`) is unchanged and continues to work exactly as before — internally it now mints a core-side `HandleTable` entry, performs the one-time `read_secret` against it immediately, and caches the result on the returned `WasmAuthorization`, so `claims` no longer carries the raw secret (`val`) across the WASM boundary at all; the secret was already redacted from the observable `claims` shape before this change, and still is.

`resolveSecretClaims(handleId)` lets a caller re-fetch the same non-secret claims later from the retained handle (refusing a signing-key handle with `AuthorizationDenied`), and `releaseHandle(handleId)` lets a caller evict the handle explicitly once done with it rather than waiting on expiry or the table's FIFO size cap. These are the primitives a future handle-based engine swap builds on directly instead of the eager `authorize()` wrapper; no existing caller needs to change.
