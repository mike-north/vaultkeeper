---
'vaultkeeper': patch
'@vaultkeeper/wasm': patch
---

Preserve unreadable key state during initialization and key updates. Coordinate persisted key updates with native writers in the built-in Node host. Native and built-in WASM hosts publish the first snapshot and wrapping key without overwriting files restored during initialization.

Accept previously persisted fractional grace expiries and write new expiries as integral milliseconds for native compatibility.

Clear displaced in-memory key buffers when persisted state is reloaded.

Recover abandoned native-format key-state locks in the TypeScript SDK.
