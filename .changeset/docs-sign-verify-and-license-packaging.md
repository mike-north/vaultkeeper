---
'vaultkeeper': patch
'@vaultkeeper/cli': patch
'@vaultkeeper/wasm': patch
'@vaultkeeper/test-helpers': patch
'@vaultkeeper/cli-test-helpers': patch
---

Ship a per-package `LICENSE` and align docs for signing/verification and packaging.

- Every published package now carries its own `LICENSE` file and lists `LICENSE` + `README.md` explicitly in its `files` array, so the packaging declaration matches what npm actually ships (previously only a root `LICENSE` existed, which `npm pack` does not include in per-package tarballs). A packaging test now asserts `LICENSE` is present in each tarball.
- Documented `sign()`'s precondition that the stored secret must be **PEM private-key** material — secrets are stored as strings and `crypto.createPrivateKey()` treats a string as PEM, so raw binary DER must be converted to PEM before storing; a plain-string secret throws `InvalidKeyMaterialError`. Added a distinct example key and a runnable end-to-end `generateKeyPairSync` → store → sign → verify walkthrough, plus `InvalidKeyMaterialError` in the repository README's error table.
- Scoped the delegated access patterns (`fetch()`/`exec()`/`getSecret()`/`sign()`/`verify()`) explicitly to the TypeScript library and clarified that `@vaultkeeper/wasm`'s `executablePath` is a non-enforcing claim label, unlike this library's TOFU-verified `executablePath`.
- Added a `getSecret()` code sample, a top-of-README quick-links/TL;DR block, a note that doctor deliberately checks all supported backends' tooling, and a more precise TypeScript-version note that shows the exact known-good consumer `compilerOptions` the CI matrix verifies across TypeScript 5.0.4–7.0.2.
