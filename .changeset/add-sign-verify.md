---
"vaultkeeper": minor
---

Add delegated signing and static verification to VaultKeeper.

`VaultKeeper.sign()` signs arbitrary data using a private key stored in the vault, returning a base64-encoded signature without exposing the key to the caller. `VaultKeeper.verify()` is a static method that verifies a signature against a public key and requires no VaultKeeper instance. New exported types: `SignRequest`, `SignResult`, `VerifyRequest`.
