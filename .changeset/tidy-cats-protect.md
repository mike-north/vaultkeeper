---
'vaultkeeper': patch
'@vaultkeeper/wasm': patch
---

Preserve unreadable key state during initialization and key updates. Coordinate persisted key updates with native writers in the built-in Node host.

Accept previously persisted fractional grace expiries and write new expiries as integral milliseconds for native compatibility.

Clear displaced in-memory key buffers when persisted state is reloaded.
