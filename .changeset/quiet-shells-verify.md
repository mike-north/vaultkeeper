---
'@vaultkeeper/wasm': minor
---

Enforce `minTrust` for plaintext and lease entries in the Rust profile resolver. Replace `ResolveOptions::executable_hash` with `executable_identity`, which borrows evidence from the executable verifier. Native `run` uses the selected executable's verification for protected profile entries and token `--set` overlays. On Unix, protected runs preserve the invocation path that scripts receive in `$0`, including symlink aliases. The WASM package version also sets the Cargo workspace version.
