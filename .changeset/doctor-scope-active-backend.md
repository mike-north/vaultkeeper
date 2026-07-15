---
'vaultkeeper': minor
'@vaultkeeper/cli': minor
'@vaultkeeper/wasm': minor
---

Scope `doctor` to the active/configured backend so a fresh install no longer looks broken. Previously `doctor` rendered every non-`'ok'` check with a failing `✗` icon, including plugin-backend tools (`ykman`, `op`) that weren't configured — on the post-#98 `file`-default install, this meant the very first `doctor` run showed a failing check for a YubiKey/1Password tool the user never opted into.

`PreflightResult.checks` entries are now `ScopedPreflightCheck` (a `PreflightCheck` plus `required: boolean`), reflecting whether each dependency is required for the active/configured backend(s). The CLI only renders the `✗` icon for checks that are both required and failing; unmet optional checks still surface, without the failure icon, in the `Warnings` section. Opt-in backends still get their dependency checks promoted to required when configured (e.g. `--backend yubikey` requires `ykman`).
