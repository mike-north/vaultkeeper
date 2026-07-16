---
'vaultkeeper': patch
'@vaultkeeper/wasm': patch
'@vaultkeeper/cli': patch
---

Polish setup() editor guidance and CLI/README papercuts.

**`setup()` compile-error hint.** Both `VaultKeeper.setup()` in the `vaultkeeper` library and `@vaultkeeper/wasm` now carry a TSDoc note that names the exact compile errors a missing trust choice produces (TS2554/TS2345) and the two remedies — add exactly one of `executablePath` or `skipTrust: true` — so hovering the call in-editor explains the fix rather than leaving the bare compiler message. The WASM `setup()` also gains a runnable `@example`.

**`useLimit` "use" semantics documented.** The README now spells out that `useLimit` bounds calls to `vault.authorize(jwe)`, not downstream delegated `fetch()`/`exec()`/`getSecret()` calls: each `authorize(jwe)` consumes one use, and the resulting `CapabilityToken` can be reused across many delegated calls; only a second `authorize(jwe)` throws `UsageLimitExceededError`.

**`verify` inline-PEM parsing.** `vaultkeeper verify --public-key`/`--signature` now reject inline PEM material with a clear, actionable usage error (exit 2) instead of node's opaque "argument is ambiguous" — the flags are file-path-only, and the message says so and points at the `--public-key=<path>` escape for a path that legitimately begins with a dash.

**Unknown-command suggestion.** An unrecognized subcommand now prints an npm/git/cargo-style `Did you mean '<closest>'?` suggestion (e.g. `doctro` → `doctor`) plus a one-line pointer to `vaultkeeper --help` and the docs, giving tarball-only users a discovery path.

**README Quick Start.** The CLI Quick Start code block now includes an inline `--config-dir`/`VAULTKEEPER_CONFIG_DIR` reminder so a copy-paster gets the isolated-config guidance that was previously only in prose.
