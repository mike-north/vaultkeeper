---
'@vaultkeeper/wasm': patch
---

Fix the Rust core's zero-config default backend to be `file` on every platform, matching the `vaultkeeper` (TS) package's #98 fix.

Previously, when no `config.json` existed, the Rust core (and therefore `@vaultkeeper/wasm`, which wraps it) fell back to a platform-native backend — `keychain` on macOS, `dpapi` on Windows — instead of the portable, self-contained AES-256-GCM encrypted `file` backend. This silently wrote secrets into the real OS keychain/credential store for any consumer that never wrote an explicit config, reintroducing the exact regression #98 fixed on the TypeScript side. Explicit configuration that selects `keychain`/`dpapi` is unaffected; only the zero-config fallback changed.
