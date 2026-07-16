---
'@vaultkeeper/cli': patch
---

Fix the README `sign`/`verify` walkthrough so a verbatim copy-paste succeeds. The example previously fed `sign` its payload with `printf '%s'` (no trailing newline) but `verify` with a here-string (`<<<`), which bash and zsh terminate with an appended `\n`. `sign` and `verify` therefore operated on byte-different payloads and the detached EdDSA signature failed with "Signature did not verify." (exit 3). Both commands now read byte-identical stdin via `printf '%s' "$CHALLENGE" | vaultkeeper …`, with an inline note that a here-string or `echo` appends a newline that breaks verification.
