---
'vaultkeeper': patch
'@vaultkeeper/wasm': patch
---

Align JWE trust-tier claims across TypeScript and Rust. New tokens use string tiers; both runtimes accept legacy numeric tiers.

Reject non-integer numeric tier spellings consistently and avoid recording executable trust when token creation fails.
