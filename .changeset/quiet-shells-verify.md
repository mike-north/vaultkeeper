---
'@vaultkeeper/wasm': minor
---

Enforce `minTrust` for plaintext and lease entries in the Rust profile resolver. Replace `ResolveOptions::executable_hash` with `executable_identity`, which borrows evidence from the executable verifier. Native `run` uses the selected executable's verification for protected profile entries and token `--set` overlays. On Unix, select an approved native interpreter explicitly to use a script with protected entries. This prevents an implicit interpreter from receiving the protected environment through a script's approval. The WASM package version also sets the Cargo workspace version.
