# @vaultkeeper/cli-test-helpers

## 0.3.0

### Minor Changes

- [#92](https://github.com/mike-north/vaultkeeper/pull/92) [`75685ac`](https://github.com/mike-north/vaultkeeper/commit/75685ac1369870f901a7fdcecd815130d42355be) Thanks [@mike-north](https://github.com/mike-north)! - Add a global `--config-dir <path>` flag / `VAULTKEEPER_CONFIG_DIR` environment variable to the CLI so every command (`store`, `delete`, `exec`, `approve`, `dev-mode`, `doctor`, `config`, `rotate-key`, `revoke-key`) can be pointed at an isolated config directory — the flag wins over the env var, which wins over the platform default. `config init` creates the override directory as needed, and `config show` reports the path it loaded from. The library's `getDefaultConfigDir()` and `loadConfig()` are now public so embedders and the CLI share the same resolution logic. `@vaultkeeper/cli-test-helpers`'s `createCliTestEnv()` gains a `configDirMode` option (`'env'` | `'flag'`) and no longer manipulates the subprocess's `HOME` directory to achieve isolation.

### Patch Changes

- [#187](https://github.com/mike-north/vaultkeeper/pull/187) [`a822564`](https://github.com/mike-north/vaultkeeper/commit/a8225649de1d9ab062055ef3eab96374cc31e2f9) Thanks [@mike-north](https://github.com/mike-north)! - Ship a per-package `LICENSE` and align docs for signing/verification and packaging.
  - Every published package now carries its own `LICENSE` file and lists `LICENSE` + `README.md` explicitly in its `files` array, so the packaging declaration matches what npm actually ships (previously only a root `LICENSE` existed, which `npm pack` does not include in per-package tarballs). A packaging test now asserts `LICENSE` is present in each tarball.
  - Documented `sign()`'s precondition that the stored secret must be **PEM private-key** material — secrets are stored as strings and `crypto.createPrivateKey()` treats a string as PEM, so raw binary DER must be converted to PEM before storing; a plain-string secret throws `InvalidKeyMaterialError`. Added a distinct example key and a runnable end-to-end `generateKeyPairSync` → store → sign → verify walkthrough, plus `InvalidKeyMaterialError` in the repository README's error table.
  - Scoped the delegated access patterns (`fetch()`/`exec()`/`getSecret()`/`sign()`/`verify()`) explicitly to the TypeScript library and clarified that `@vaultkeeper/wasm`'s `executablePath` is a non-enforcing claim label, unlike this library's TOFU-verified `executablePath`.
  - Added a `getSecret()` code sample, a top-of-README quick-links/TL;DR block, a note that doctor deliberately checks all supported backends' tooling, and a more precise TypeScript-version note that shows the exact known-good consumer `compilerOptions` the CI matrix verifies across TypeScript 5.0.4–7.0.2.

- [#84](https://github.com/mike-north/vaultkeeper/pull/84) [`c521414`](https://github.com/mike-north/vaultkeeper/commit/c521414caf844cf7d740e25faf271bcb320360f5) Thanks [@mike-north](https://github.com/mike-north)! - Remove the top-level `package.json#types` field, which pointed at an API Extractor rollup (`dist/<name>-public.d.ts`) that the release pipeline never generates before `changeset publish` and was therefore absent from the published tarball. Types now resolve entirely through the conditional `exports` map, which already pointed at the real per-format `tsup` output. `@vaultkeeper/cli-test-helpers`'s `exports` conditions, which had the same stale rollup reference, now point at the real `dist/index.d.ts` / `dist/index.d.cts` files as well.

  Confirms (and now enforces via a packaging test) that only `@vaultkeeper/cli` declares the `vaultkeeper` bin — the `vaultkeeper` library package was already free of a `bin` field in this repo, but the registry had previously observed contradictory bin ownership across published versions.

- [#77](https://github.com/mike-north/vaultkeeper/pull/77) [`26c876c`](https://github.com/mike-north/vaultkeeper/commit/26c876c4ba58eff1639cf6e2307f8c01fe5d85bd) Thanks [@mike-north](https://github.com/mike-north)! - Ship a package-specific README.md and `repository`/`homepage`/`bugs` metadata with every published package, so registry consumers get install instructions and a quick start without leaving npm.

## 0.2.0

### Minor Changes

- [#20](https://github.com/mike-north/vaultkeeper/pull/20) [`c65c107`](https://github.com/mike-north/vaultkeeper/commit/c65c1076802dcc5e2710c47fd60e3f1771858fe1) Thanks [@mike-north](https://github.com/mike-north)! - Add VAULTKEEPER_CONFIG_DIR env var for test isolation and introduce @vaultkeeper/cli-test-helpers package with reusable CLI test infrastructure
