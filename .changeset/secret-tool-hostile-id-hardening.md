---
"vaultkeeper": patch
---

Harden the Linux `secret-tool` backend: a `--` separator now precedes every positional attribute/id argument so ids beginning with dashes cannot be parsed as flags; not-found detection depends solely on the exit code, and `retrieve()` strips exactly one trailing newline instead of trimming, so empty and whitespace-only secret values round-trip byte-for-byte.
