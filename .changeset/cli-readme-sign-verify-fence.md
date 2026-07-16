---
'@vaultkeeper/cli': patch
'vaultkeeper': patch
---

Fixed the CLI README's sign/verify walkthrough: `sign` and `verify` now both read the challenge via `printf '%s'`, so each sees byte-identical stdin — the previous here-string form appended a trailing newline, making the documented example fail verification with exit 3. Shipped READMEs' runnable examples are now exercised by a CI example-fence check so a documented command sequence that stops working fails the build.
