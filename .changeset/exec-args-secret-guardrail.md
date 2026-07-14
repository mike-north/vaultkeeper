---
'vaultkeeper': patch
---

Fix a security gap in `delegatedExec`: `{{secret}}` (or `{{secret:name}}`) in any `args` element was silently substituted with the raw secret value, exposing it on the process command line where it is visible to other processes via `ps` and often collected in logs and telemetry. `exec()` now throws `ExecError` if a placeholder appears in `args`, matching the existing `command`-field guardrail. Inject secrets via `env` instead.

This is a breaking-in-practice fix: any caller that relied on placeholder substitution inside `args` will now get `ExecError` and must move the secret into `env`.
