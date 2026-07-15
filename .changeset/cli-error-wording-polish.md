---
'vaultkeeper': patch
'@vaultkeeper/cli': patch
---

Fix CLI error-experience papercuts:

- `exec` and `delete` now report an identical "secret not found" message (`Secret "<name>" not found in the "<backend>" backend.`) with a recovery hint (`Run \`vaultkeeper store --name <name>\` to create it.`) — previously each surfaced different wording and neither pointed at a fix.
- `store` with empty stdin now exits 2 (usage error) instead of 1, consistent with a missing or empty `--name` — both mean "no usable input was given."
- The library's `ConfigValidationError` message now separates the validation diagnosis from the remediation hint with a period instead of running them together with no punctuation.
