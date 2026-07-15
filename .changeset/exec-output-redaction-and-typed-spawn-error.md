---
'vaultkeeper': minor
'@vaultkeeper/cli': patch
---

Redact injected secrets from library `exec()` output, and give the CLI a typed error when a wrapped command cannot be spawned.

- `VaultKeeper.exec()` now redacts every injected secret value from the captured `stdout`/`stderr` before returning, replacing each occurrence with `[REDACTED]`. This upholds the documented guarantee that the raw secret never appears in the return value, even when the spawned command echoes it. Multi-secret (`{{secret:name}}`) injections redact all injected values. Pass the new `ExecRequest.redact: false` to opt out and receive raw output. The redaction logic is shared with the CLI's streaming `--no-redact` path via the new public `redactSecrets` helper, so the two surfaces cannot drift.
- The CLI `exec` command now maps a spawn failure of the wrapped command (`ENOENT` for a nonexistent command, `EACCES` for a non-executable file) to a typed `ExecError` with remediation, rendered through the CLI's typed-error formatter, instead of leaking a bare `Error: spawn <path> ENOENT`.
