---
"@vaultkeeper/wasm": minor
---

Introduce the environment profile primitive in `vaultkeeper-core` (issue #277): serde schema, a fail-closed loader, and `profile init/show/list/lint` in the Rust CLI. Profiles are named, declarative binding sets (env-var name → secret source → materialization mode → policy) stored at `$CONFIG_DIR/profiles/<name>.json`, never inside `config.json`.

`@vaultkeeper/wasm` gains the `MaterializeModeUnsupportedError` typed error class (and its `materialize-mode-unsupported` error code), thrown when a profile's `materialize` field uses the reserved-but-not-yet-implemented object form (`{ "mode": "reference", ... }`).
