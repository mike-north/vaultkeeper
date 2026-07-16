---
'vaultkeeper': patch
'@vaultkeeper/cli': patch
---

Surface the offending field in `doctor`'s remediation for a schema-invalid config.

For a config that parses as JSON but fails schema validation (e.g. `backends: []`), `doctor`'s Next-steps previously said only that the config was invalid, omitting the field-level reason it gives for JSON-parse errors (which name the line/column). The `PreflightCheckError` structured context now carries the offending `field` for a `config-validation` failure — the validation analogue of a parse failure's `location` — so `doctor` renders it (e.g. "is invalid (`backends`)"), matching the wording every other command already used. No `reason` prose is parsed to do this.
