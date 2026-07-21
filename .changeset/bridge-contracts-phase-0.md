---
"@vaultkeeper/wasm": minor
---

Phase 0 bridge contracts for the consolidation effort (issue #239): the Rust `HostPlatform` trait and its WASM/JS bridge gain the primitives a host-implemented backend and delegated network access will need in later phases.

`HostPlatform::exec` now accepts an `ExecOptions` bundle (`stdin`, `env`, `cwd`) instead of a bare `stdin` argument — `@vaultkeeper/wasm`'s `WasmHostPlatform.exec` mirrors this with an optional third `options` argument, and `createNodeHost()` implements `env` as `{ ...process.env, ...options.env }` and `cwd` via `child_process.execFile`'s own `cwd` option. Omitting `options` (or any of its fields) reproduces the exact pre-#239 behavior — no existing caller's behavior changes.

A new `HostPlatform::http_fetch` primitive lands with its `@vaultkeeper/wasm` counterpart `WasmHostPlatform.httpFetch`, implemented in `createNodeHost()` over the global `fetch`. No core consumer calls it yet — the delegated-access port in a later issue is the first real caller — but the primitive is fully wired end-to-end and covered by direct tests today.

A new optional `HostPlatform::prompt_approval` capability lets a host offer interactive human approval for a sensitive action; an absent implementation (the default on every existing host) fails closed (`false`) rather than auto-approving. `@vaultkeeper/wasm` exposes this as the optional `WasmHostPlatform.promptApproval` method.

`@vaultkeeper/wasm` also publishes a new `HostSecretBackend` contract type — the shape a JS/TS-implemented secret backend must satisfy to be driven by the Rust core — backed by a new `JsSecretBackend` scaffold in `crates/vaultkeeper-wasm` that dispatches `store`/`retrieve`/`delete`/`exists`/`list` over JS callbacks (all-async, `Uint8Array` at the boundary, never `Buffer`). Registry dispatch and the capability/signing methods on the contract (`getCapabilities`, `generateSigningKey`, `getPublicKey`, `signWithKey`) are forward-looking — not yet wired to Rust — pending the capability trait (issue #242) and signing trait (issue #237).
