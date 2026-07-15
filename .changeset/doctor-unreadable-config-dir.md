---
'vaultkeeper': minor
'@vaultkeeper/cli': patch
---

Render an unreadable config directory as a failing doctor check instead of a raw crash.

- `vaultkeeper doctor` run against a config directory the process cannot read (e.g. a `chmod 000` directory, so reading `config.json` inside it fails with `EACCES`/`EPERM`) previously aborted with a raw Node `Error: EACCES: permission denied, access '.../config.json'` — no typed class, no fix hint, and no checks rendered at all. It now surfaces the read failure as a failing `config` check (just like a parse or validation failure), keeps rendering the other checks, prints a permissions-oriented remediation under "Next steps", and exits non-zero. The raw errno string no longer leaks to the user.
- The public `PreflightCheckErrorKind` gains a `'config-read'` member, and `PreflightCheckError` gains an optional `code` field carrying the underlying errno (e.g. `EACCES`), so a consumer can build a permissions-specific remediation. `config init --force` is deliberately not suggested for this failure — it cannot repair a config the process cannot read.
