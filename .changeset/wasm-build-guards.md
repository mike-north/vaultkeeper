---
"@vaultkeeper/wasm": patch
---

Rebuild the committed WASM binary with explicit `wasm-opt -Oz` optimization (previously relying on wasm-pack's implicit default). No runtime API changes — the artifact is smaller, not different in behavior.
