---
'@vaultkeeper/wasm': patch
---

Fix the WASM SDK failing to read a config directory produced by the documented `vaultkeeper config init` flow. `config init` (and the README example) writes `defaults.trustTier` as a bare JSON number (`3`), but the Rust-core config reader behind the SDK required a string-encoded number, so `createVaultKeeper()` threw `VaultError: Failed to parse config` on a CLI-produced config.

The core config reader now accepts `trustTier` as either a bare number (`3`) or a string-encoded number (`"3"`), and writes the bare-number form — aligning the native CLI output, the TS CLI, the TS library, and the README on one canonical wire form while remaining backward compatible with existing string-form configs. The `tid` claim in JWE tokens is unchanged and keeps its string wire form.
