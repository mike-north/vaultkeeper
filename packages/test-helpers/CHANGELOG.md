# @vaultkeeper/test-helpers

## 0.3.0

### Minor Changes

- [#131](https://github.com/mike-north/vaultkeeper/pull/131) [`f2fe1d2`](https://github.com/mike-north/vaultkeeper/commit/f2fe1d2c4c3ade6e00680de65c4872aacfcc9793) Thanks [@mike-north](https://github.com/mike-north)! - Breaking (0.x): `VaultKeeper.setup()` now requires an explicit executable-trust choice. Versioned as a minor bump under 0.x semver (breaking changes ship as minor bumps while `vaultkeeper` is pre-1.0).

  `setup()` previously defaulted `executablePath` to `'dev'` when omitted, which silently skipped Trust On First Use (TOFU) executable-identity verification — so a bare `await vault.setup(name)` minted an unverified token even though the caller may have believed trust was enforced. This was a permissive security default for a secrets tool. Existing `setup(name)` calls must now pass `executablePath` (runs TOFU verification) or `skipTrust: true` (development-only opt-out); omitting both throws `ExecutableTrustRequiredError`.

  `setup()` now requires the caller to make the decision explicitly. Provide exactly one of:
  - `executablePath` — the calling executable's real path, which runs TOFU verification (the safe, production choice), or
  - `skipTrust: true` — a self-describing, greppable, development-only opt-out that deliberately skips verification.

  Supplying neither — or both — now throws the new typed `ExecutableTrustRequiredError` (a `VaultError` subclass, exported from the package root) instead of silently skipping trust. Its `reason` field is `'missing-choice'`, `'conflicting-choice'`, or `'legacy-dev-sentinel'` (the retired `executablePath: 'dev'` opt-out).

  Passing a real `executablePath` behaves exactly as before, including the existing `setDevelopmentMode()` allowlist bypass and `IdentityMismatchError` on a hash conflict.

  **Migration** — every existing `setup()` call must now name a trust choice:

  ```ts
  // Before — unverified by default (silent skip):
  await vault.setup('MY_API_KEY')

  // After — verify the calling executable (production):
  await vault.setup('MY_API_KEY', { executablePath: process.argv[1] })

  // After — deliberately skip verification (development/tests only):
  await vault.setup('MY_API_KEY', { skipTrust: true })
  ```

  Callers that previously passed the `'dev'` sentinel must switch to the dedicated opt-out — the legacy `'dev'` sentinel is no longer supported and is now rejected at runtime with an `ExecutableTrustRequiredError` (`reason: 'legacy-dev-sentinel'`) instead of being resolved as a real path:

  ```ts
  // Before:
  await vault.setup('MY_API_KEY', { executablePath: 'dev' })
  // After:
  await vault.setup('MY_API_KEY', { skipTrust: true })
  ```

  `@vaultkeeper/test-helpers`: `TestVault` gains a `setup(name, options?)` convenience method that defaults to `skipTrust: true`, so consumer tests calling it stay hermetic without naming a real executable. Pass `executablePath` to exercise real verification instead.

- [#56](https://github.com/mike-north/vaultkeeper/pull/56) [`9fc3eeb`](https://github.com/mike-north/vaultkeeper/commit/9fc3eebf44514e5bdd6e140fd87077bc5c0e0413) Thanks [@mike-north](https://github.com/mike-north)! - Add `store()` and `delete()` convenience methods to `TestVault`. Moves `vaultkeeper` from `dependencies` to `peerDependencies` to fix a dual-package hazard that caused `instanceof` checks on `VaultError` subclasses to fail in some consumer setups. Consumers must now list `vaultkeeper` as a direct dependency.

- [#196](https://github.com/mike-north/vaultkeeper/pull/196) [`7ee1a61`](https://github.com/mike-north/vaultkeeper/commit/7ee1a61b15a044db2444970adc2c3d7013f5fa47) Thanks [@mike-north](https://github.com/mike-north)! - Type-enforce the `setup()` trust choice, fix the quick-start rebuild footgun, and polish docs and CLI usage errors.

  **`SetupOptions` is now a discriminated union (type-enforced trust XOR).** `VaultKeeper.setup()`'s options argument is required and must carry **exactly one** of `executablePath` (TOFU verification) or `skipTrust: true` (development opt-out). Supplying neither — including a bare `setup('NAME')` or `setup('NAME', {})` — or both is now a **compile-time** error rather than a runtime-only failure; `ExecutableTrustRequiredError` remains the runtime backstop for untyped (plain-JavaScript) callers. `SetupOptionsBase` is exported for the common (non-trust) options. `@vaultkeeper/test-helpers` gains a matching public `TestVaultSetupOptions` type; `TestVault.setup()` keeps its permissive, trust-choice-optional signature (it still defaults to `skipTrust: true`).

  **Quick-start rebuild footgun fixed.** The library quick start no longer steers first-timers to `executablePath: process.argv[1]`, which pins TOFU trust to the compiled entry-file hash and throws `IdentityMismatchError` on the next run after any rebuild. The runnable snippets now use the development-safe `{ skipTrust: true }`, with an inline warning and a clearly-framed production example that binds a **stable** anchor (a released binary or `process.execPath`), plus a cross-reference to Development mode for frequently-rebuilt local callers.

  **Docs and CLI papercuts.** Documented `exec()`'s `[REDACTED]`-by-default output redaction and the `redact: false` opt-out in the library README; clarified that `VaultKeeper.init()` is in-memory and does not write `config.json` (only the CLI `config init` does); clarified that pre-approving a caller is a required first step for non-interactive/CI first `exec` (CLI) versus auto-recorded on first encounter (library); and documented the WASM `doctor()` unscoped required-vs-informational semantics. The CLI now prints a `Usage:` block (and exits 2) for an unknown top-level flag, matching the unknown-command and subcommand-level usage errors.

### Patch Changes

- [#187](https://github.com/mike-north/vaultkeeper/pull/187) [`a822564`](https://github.com/mike-north/vaultkeeper/commit/a8225649de1d9ab062055ef3eab96374cc31e2f9) Thanks [@mike-north](https://github.com/mike-north)! - Ship a per-package `LICENSE` and align docs for signing/verification and packaging.
  - Every published package now carries its own `LICENSE` file and lists `LICENSE` + `README.md` explicitly in its `files` array, so the packaging declaration matches what npm actually ships (previously only a root `LICENSE` existed, which `npm pack` does not include in per-package tarballs). A packaging test now asserts `LICENSE` is present in each tarball.
  - Documented `sign()`'s precondition that the stored secret must be **PEM private-key** material — secrets are stored as strings and `crypto.createPrivateKey()` treats a string as PEM, so raw binary DER must be converted to PEM before storing; a plain-string secret throws `InvalidKeyMaterialError`. Added a distinct example key and a runnable end-to-end `generateKeyPairSync` → store → sign → verify walkthrough, plus `InvalidKeyMaterialError` in the repository README's error table.
  - Scoped the delegated access patterns (`fetch()`/`exec()`/`getSecret()`/`sign()`/`verify()`) explicitly to the TypeScript library and clarified that `@vaultkeeper/wasm`'s `executablePath` is a non-enforcing claim label, unlike this library's TOFU-verified `executablePath`.
  - Added a `getSecret()` code sample, a top-of-README quick-links/TL;DR block, a note that doctor deliberately checks all supported backends' tooling, and a more precise TypeScript-version note that shows the exact known-good consumer `compilerOptions` the CI matrix verifies across TypeScript 5.0.4–7.0.2.

- [#84](https://github.com/mike-north/vaultkeeper/pull/84) [`c521414`](https://github.com/mike-north/vaultkeeper/commit/c521414caf844cf7d740e25faf271bcb320360f5) Thanks [@mike-north](https://github.com/mike-north)! - Remove the top-level `package.json#types` field, which pointed at an API Extractor rollup (`dist/<name>-public.d.ts`) that the release pipeline never generates before `changeset publish` and was therefore absent from the published tarball. Types now resolve entirely through the conditional `exports` map, which already pointed at the real per-format `tsup` output. `@vaultkeeper/cli-test-helpers`'s `exports` conditions, which had the same stale rollup reference, now point at the real `dist/index.d.ts` / `dist/index.d.cts` files as well.

  Confirms (and now enforces via a packaging test) that only `@vaultkeeper/cli` declares the `vaultkeeper` bin — the `vaultkeeper` library package was already free of a `bin` field in this repo, but the registry had previously observed contradictory bin ownership across published versions.

- [#173](https://github.com/mike-north/vaultkeeper/pull/173) [`ee287c9`](https://github.com/mike-north/vaultkeeper/commit/ee287c90bbc73448a0e8a5483bab59177f2710c0) Thanks [@mike-north](https://github.com/mike-north)! - Loosen the `vaultkeeper` peerDependency range from `workspace:^` (published as `^0.6.0`) to an explicit `>=0.6.0 <1`. The caret range was minor-locked under 0.x, so a routine `vaultkeeper` minor bump (e.g. 0.6.0 → 0.7.0) would exit the range and trigger a changesets-driven major bump on `@vaultkeeper/test-helpers` — silently graduating it to 1.0.0 with no changeset declaring that intent. The new range tracks the pre-1.0 vaultkeeper line explicitly and only forces a major on `@vaultkeeper/test-helpers` once `vaultkeeper` itself reaches 1.0.0, which is the point such a cascade should actually happen.

  This also requires enabling changesets' `onlyUpdatePeerDependentsWhenOutOfRange` option (see `.changeset/config.json`): by default, changesets bumps a package major on _any_ non-patch release of a peer dependency, regardless of whether the new version still satisfies the declared peer range. Without that option, the widened range alone would not have stopped the cascade.

- [#77](https://github.com/mike-north/vaultkeeper/pull/77) [`26c876c`](https://github.com/mike-north/vaultkeeper/commit/26c876c4ba58eff1639cf6e2307f8c01fe5d85bd) Thanks [@mike-north](https://github.com/mike-north)! - Ship a package-specific README.md and `repository`/`homepage`/`bugs` metadata with every published package, so registry consumers get install instructions and a quick start without leaving npm.

- [#175](https://github.com/mike-north/vaultkeeper/pull/175) [`f20ea5a`](https://github.com/mike-north/vaultkeeper/commit/f20ea5a1aeded6fbdeaf0a937623737f5bc9c756) Thanks [@mike-north](https://github.com/mike-north)! - Round out the shipped package docs so a reader offline (registry-only, air-gapped) can find everything without the GitHub URL:
  - `vaultkeeper` README: new "Multiple secrets in one request" section documenting `SecretTokenMap` and the `{{secret:name}}` placeholder for injecting several secrets into one `fetch()`/`exec()` call; a runnable inline `exec()` example (secret injected via `env`); a complete error-types table covering all `VaultError` subclasses; a full `VaultConfig`/`BackendConfig` field reference; and a "Doctor / preflight checks" section explaining required-vs-informational checks and that a plugin checkmark means "binary detected on PATH", not "backend active".
  - `vaultkeeper` README: `verify()` now notes that the disallowed-algorithm throw does not apply to Ed25519/Ed448 keys (the algorithm override is ignored). The "Testing against this library" section notes `@vaultkeeper/test-helpers` belongs in `devDependencies` and warns that the real `VaultKeeper.setup()` always requires `executablePath` or `skipTrust`.
  - `@vaultkeeper/test-helpers` README: strengthened the warning that the test-only zero-arg `setup()` default does not carry over to the real `VaultKeeper.setup()`.
  - `@vaultkeeper/cli` README: new "Doctor / preflight checks" section on checkmark semantics — plugin checks (`op`/`ykman`) are informational when their backend isn't enabled, but enabling the `1password`/`yubikey` backend promotes its tool check to required; points at the now-self-contained library README for the full error hierarchy and config reference.

## 0.2.7

### Patch Changes

- [`5bbff5a`](https://github.com/mike-north/vaultkeeper/commit/5bbff5a7c6129a5240b3307c6915e4957b3889c1) Thanks [@mike-north](https://github.com/mike-north)! - Standardize authorize() return type to use vaultResponse (matching exec/fetch/sign), accept RunDoctorOptions in VaultKeeper.doctor(), and include reason in required dependency error messages

- Updated dependencies [[`5bbff5a`](https://github.com/mike-north/vaultkeeper/commit/5bbff5a7c6129a5240b3307c6915e4957b3889c1), [`5bbff5a`](https://github.com/mike-north/vaultkeeper/commit/5bbff5a7c6129a5240b3307c6915e4957b3889c1), [`a7540d1`](https://github.com/mike-north/vaultkeeper/commit/a7540d1b2198dceace73c1e1abba2dcd0f565f03), [`a7540d1`](https://github.com/mike-north/vaultkeeper/commit/a7540d1b2198dceace73c1e1abba2dcd0f565f03)]:
  - vaultkeeper@0.6.0

## 0.2.6

### Patch Changes

- Updated dependencies [[`a037cd6`](https://github.com/mike-north/vaultkeeper/commit/a037cd6e540ede350bc8a681a5ebbea8296a3793)]:
  - vaultkeeper@0.5.3

## 0.2.5

### Patch Changes

- [#44](https://github.com/mike-north/vaultkeeper/pull/44) [`3b5868f`](https://github.com/mike-north/vaultkeeper/commit/3b5868f676e6b4131e5d99c244246c7cbb325845) Thanks [@mike-north](https://github.com/mike-north)! - Fix error type correctness: `InMemoryBackend` now throws `SecretNotFoundError` (not plain `Error`), exceeding a token's use limit throws `UsageLimitExceededError` (not `TokenRevokedError`), and double-reading a `SecretAccessor` throws a descriptive error instead of a raw Proxy `TypeError`.

- Updated dependencies [[`f0fe162`](https://github.com/mike-north/vaultkeeper/commit/f0fe16247ebcfc33ad0dd65a57695a101ca07b61), [`3b5868f`](https://github.com/mike-north/vaultkeeper/commit/3b5868f676e6b4131e5d99c244246c7cbb325845)]:
  - vaultkeeper@0.5.2

## 0.2.4

### Patch Changes

- Updated dependencies [[`003e497`](https://github.com/mike-north/vaultkeeper/commit/003e4972c6bf1c4b39e838ed32346a84e4396bee)]:
  - vaultkeeper@0.5.1

## 0.2.3

### Patch Changes

- Updated dependencies [[`c65c107`](https://github.com/mike-north/vaultkeeper/commit/c65c1076802dcc5e2710c47fd60e3f1771858fe1), [`3f95e3b`](https://github.com/mike-north/vaultkeeper/commit/3f95e3b954cb6f046e34f2155da9ff945d47c16e)]:
  - vaultkeeper@1.0.1

## 0.2.2

### Patch Changes

- Updated dependencies [[`5353518`](https://github.com/mike-north/vaultkeeper/commit/535351866ef9cb4e77edb9b2b757911e74b3b402), [`c0d36c5`](https://github.com/mike-north/vaultkeeper/commit/c0d36c5f5bdc7848574863514bfe53e23ce83d42)]:
  - vaultkeeper@1.0.0

## 0.2.1

### Patch Changes

- Updated dependencies [[`a1d2e57`](https://github.com/mike-north/vaultkeeper/commit/a1d2e57fe3b2132d63755c31acc332b90ae7a799)]:
  - vaultkeeper@0.4.0

## 0.2.0

### Minor Changes

- [#9](https://github.com/mike-north/vaultkeeper/pull/9) [`c2c4e8c`](https://github.com/mike-north/vaultkeeper/commit/c2c4e8cfd94e624b4ad7dfd2f3b22a6046d91c8e) Thanks [@mike-north](https://github.com/mike-north)! - Add `ListableBackend` interface with `list()` method for enumerating stored secrets, implemented on all backends. Add `isListableBackend()` type guard. `InMemoryBackend` now also implements `ListableBackend`.

### Patch Changes

- Updated dependencies [[`a000092`](https://github.com/mike-north/vaultkeeper/commit/a000092848e94e130893d145d07a8b8bf6fc1ead), [`c2c4e8c`](https://github.com/mike-north/vaultkeeper/commit/c2c4e8cfd94e624b4ad7dfd2f3b22a6046d91c8e), [`7398ff6`](https://github.com/mike-north/vaultkeeper/commit/7398ff6352b8d3e39e562ace50b8caa8ef998882)]:
  - vaultkeeper@0.3.0

## 0.1.1

### Patch Changes

- Updated dependencies [[`1f1412c`](https://github.com/mike-north/vaultkeeper/commit/1f1412c7b76c7810b395df4b9de44ebe21a16188)]:
  - vaultkeeper@0.2.0

## 0.1.0

### Minor Changes

- [#1](https://github.com/mike-north/vaultkeeper/pull/1) [`7e9c1f5`](https://github.com/mike-north/vaultkeeper/commit/7e9c1f5b448ea97862aee607898f1ff84081519f) Thanks [@mike-north](https://github.com/mike-north)! - Convert to pnpm workspace monorepo and add test-helpers package
  - Restructured as a pnpm workspace with `packages/vaultkeeper` and `packages/test-helpers`
  - Added `@vaultkeeper/test-helpers` package providing `InMemoryBackend` and `TestVault` for fast, hermetic tests
  - Shared TypeScript config via `tsconfig.base.json`, shared ESLint config at workspace root
  - Added vitest workspace configuration for cross-package test execution
  - Added changesets for version and changelog management

### Patch Changes

- Updated dependencies [[`7e9c1f5`](https://github.com/mike-north/vaultkeeper/commit/7e9c1f5b448ea97862aee607898f1ff84081519f)]:
  - vaultkeeper@0.1.0
