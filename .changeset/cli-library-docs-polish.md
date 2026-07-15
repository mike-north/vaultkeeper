---
'vaultkeeper': patch
'@vaultkeeper/cli': patch
---

Document the CLI's exit-code contract (0 success / 1 runtime error / 2 usage error, with an example
of each) and the `--config-dir` flag / `VAULTKEEPER_CONFIG_DIR` env var in the CLI README. Note in
the library README that consumers need `"type": "module"` (vaultkeeper is ESM-only) and that
`useLimit` defaults to unlimited (`null`) when omitted from `setup()` options.

`RotationInProgressError`'s message now includes a next step — run `vaultkeeper revoke-key` (or
call `revokeKey()`) to invalidate the previous key immediately, or wait for the grace period to
elapse — matching the actionable-remediation style of the other domain errors.
