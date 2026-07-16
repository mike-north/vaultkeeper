---
'vaultkeeper': patch
'@vaultkeeper/cli': patch
---

Validate `backends[].type` against the registered backends when loading a config, closing a gap where `doctor` reported a false "System ready." for a config naming a backend that does not exist.

- Config validation (`loadConfig`, `validateConfig`) now rejects a `backends[].type` that names no registered backend. A config with an unknown type parses as valid JSON and is structurally valid, but the next real command would throw `BackendUnavailableError` at backend-creation time — so `doctor` reporting all-clear undermined the diagnostic the CLI's own corrupted-config recovery points users at.
- `doctor`'s config check now FAILS (red, exit non-zero) for an unknown backend type and names both the offending type and the valid options — the same guidance the runtime `BackendUnavailableError` gives — instead of silently passing.
- New public `UnknownBackendTypeError` (a `ConfigValidationError` subclass) carries the offending `backendType` and the `knownTypes`. The `doctor` preflight result gains a `config-unknown-backend` error kind carrying `backendType` and `knownBackendTypes`, so a consumer can render the valid-types guidance without parsing prose.
- The valid set is read from the backend registry (including any custom backends a consumer registered), not a hardcoded list.
