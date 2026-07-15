---
'vaultkeeper': patch
'@vaultkeeper/cli': patch
---

Close doc gaps left over from the shipped-README audit:

- `vaultkeeper`'s and `@vaultkeeper/cli`'s README `exec` examples now mention the default `[REDACTED]` output redaction and the `--no-redact` escape hatch inline.
- The `vaultkeeper` package README now inlines a development-mode explanation, a `sign()`/`verify()` example, and a brief error-hierarchy summary instead of deferring them solely to the unshipped repository README; `@vaultkeeper/cli`'s README gets an inline development-mode explanation too.
- States a supported TypeScript version (5.x) in both READMEs, and documents a `require()`/CommonJS quick-start variant alongside the existing ESM one.
- `verify()`'s JSDoc now calls out that it is synchronous and throws immediately (not via a rejected `Promise`) for a disallowed algorithm.
- Adds a `./package.json` subpath to `vaultkeeper`'s `exports` map.
