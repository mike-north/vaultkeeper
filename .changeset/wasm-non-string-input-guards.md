---
'@vaultkeeper/wasm': patch
---

Guard the WASM SDK's string arguments so a non-string input surfaces a typed, catchable error instead of crashing the process.

`VaultKeeper` forwarded its arguments straight into WebAssembly with no JS-side type check, so a non-string — a number, a plain object, or (a common mistake) an un-awaited `setup()` Promise — reached wasm-bindgen's string marshaling and aborted the process with an opaque `VaultError: memory access out of bounds` fault. A malformed token *string* by contrast already yielded a clean `InvalidTokenError`.

Every wrapper method that forwards a string into WASM now validates the JS type at the boundary, before the value crosses into WebAssembly:

- `authorize(jwe)` throws `InvalidTokenError` on a non-string `jwe` (joining the malformed-token-string case under one catchable type).
- `setup(secretName, secretValue)`, `store(id, secret)`, `retrieve(id)`, and `delete(id)` throw `TypeError` on a non-string argument, naming the offending method and parameter.
