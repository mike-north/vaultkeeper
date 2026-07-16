---
'vaultkeeper': minor
'@vaultkeeper/cli': minor
---

Add a backend `presencePerUse` capability and the ability to require it for an operation.

`presencePerUse` means "every operation with a key in this backend forces a distinct, fresh physical human action, and can never be satisfied from a cached or session-unlocked state." vaultkeeper is now the single place that knows this per configured backend instance and enforces it, so consumers never have to reason about YubiKey touch policies or 1Password per-access tricks themselves.

Library:

- New `PresenceCapableBackend` extension interface (`getCapabilities(): Promise<BackendCapabilities>`) — mirrors `ListableBackend`/`SigningBackend`; it is not a required member of `SecretBackend`. `BackendCapabilities` is `{ presencePerUse: boolean }` and is open to extension.
- New `getBackendCapabilities(backend)` helper and `isPresenceCapableBackend(backend)` guard. A backend that does not implement the interface reports `{ presencePerUse: false }` — an unknown backend never silently claims presence. The capability reflects the configured instance (a YubiKey slot's touch policy, 1Password's access mode), never a hardcoded per-type answer.
- New `VaultKeeper.getActiveBackendCapabilities()` introspection method.
- New `requirePresencePerUse?: boolean` option on the shared access path (`store`, `delete`, `setup`, `sign`). Enforcement is queried fresh on every call and refuses before any credential/session/device is touched when unsatisfied; when capable, the operation forces a fresh action for that specific call. Presence-gated signing performs a fresh backend `signWithKey` round-trip per call, so no cached key material can satisfy it.
- Enforcement is **operation-aware and fail-closed** via `BackendCapabilities.presenceEnforcedOperations` (a list of `PresenceOperation`; omitted means all operations). A backend that forces presence for only some operations refuses a flagged uncovered operation with `NotCapableError` rather than passing without a fresh action. 1Password `per-access` forces presence for reads only (`store`/`delete` route through the cached session client), so a flagged `store`/`delete` on 1Password is correctly refused; a YubiKey touch slot covers every operation.
- New typed errors (all extend `VaultError`, machine-readable fields, exported): `NotCapableError { backendType, capability }`, `PresenceDeclinedError { backendType }`, `PresenceTimeoutError { backendType, timeoutMs }`.

CLI:

- New `vaultkeeper backend capabilities [--json]` command lists each registered backend as `{ type, displayName, presencePerUse }` (a flat array with `--json`, human-readable text otherwise).
- New per-command `--require-presence-per-use` flag on `store`, `delete`, `sign`, and `exec` (never global, never on `verify`). With `exec`, a cached token is never reused under the flag.
