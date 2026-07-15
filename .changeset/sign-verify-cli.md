---
'vaultkeeper': minor
'@vaultkeeper/cli': minor
---

Make signing and verification of arbitrary challenges a first-class, CLI-exposed primitive with a stable, third-party-verifiable signature format.

- New CLI commands (`@vaultkeeper/cli`): `key create --name <n> --type ed25519` provisions a signing keypair (unknown `--type` exits 2, never a silent default); `key export --name <n>` prints the SPKI PEM public key; `sign --name <n>` reads all of stdin and writes exactly the detached signature to stdout (pipeline-safe; status on stderr); `verify --public-key <pem> --signature <sig>` verifies a detached signature fully offline (no config, backend, or key store). `verify` adds exit code `3` for a signature that did not verify — a deliberate, documented exception to the `0/1/2` taxonomy so scripts can tell a bad signature from a broken tool.
- Signatures are detached-payload Compact JWS (RFC 7515 §7.2.2 + RFC 7797 `b64:false`, `crit:["b64"]`, `alg` EdDSA/Ed25519). Any standards-compliant JOSE library can verify a signature given the payload and the public key.
- Signing keys are a distinct resource from secrets: a new backend signing contract (`generateSigningKey`/`getPublicKey`/`signWithKey`, mirroring `ListableBackend`) keeps private key material backend-side. It never flows through `store()`/`retrieve()`/`fetch()`/`exec()` or a capability token's claims, and `fetch()`/`exec()`/`getSecret()` reject a signing-key token outright. The `file` backend implements the contract; backends that do not fail with a typed `SigningNotSupportedError`.
- Breaking (library): the `SignRequest`/`SignResult`/`VerifyRequest` shapes and `VaultKeeper.sign()`/`VaultKeeper.verify()` are reshaped to the JWS contract. `sign()` now takes a signing-key capability token from the new `authorizeSigningKey()` and returns `{ jws }`; `verify()` is async and takes `{ payload, jws, publicKey }`. New public API: `createSigningKey()`, `exportPublicKey()`, `authorizeSigningKey()`, `SigningBackend`/`isSigningBackend`, `SigningAlgorithm`, `SigningPublicKey`, and the `SigningKeyNotFoundError`/`SigningNotSupportedError` typed errors.
