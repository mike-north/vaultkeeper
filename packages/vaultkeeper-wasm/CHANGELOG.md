# @vaultkeeper/wasm

## 0.3.0

### Minor Changes

- [#121](https://github.com/mike-north/vaultkeeper/pull/121) [`7c8ab85`](https://github.com/mike-north/vaultkeeper/commit/7c8ab857859049fce5d9e1518d13a2b126293540) Thanks [@mike-north](https://github.com/mike-north)! - Scope `doctor` to the active/configured backend so a fresh install no longer looks broken. Previously `doctor` rendered every non-`'ok'` check with a failing `✗` icon, including plugin-backend tools (`ykman`, `op`) that weren't configured — on the post-#98 `file`-default install, this meant the very first `doctor` run showed a failing check for a YubiKey/1Password tool the user never opted into.

  `PreflightResult.checks` entries are now `ScopedPreflightCheck` (a `PreflightCheck` plus `required: boolean`), reflecting whether each dependency is required for the active/configured backend(s). The CLI only renders the `✗` icon for checks that are both required and failing; unmet optional checks still surface, without the failure icon, in the `Warnings` section. Opt-in backends still get their dependency checks promoted to required when configured (e.g. `--backend yubikey` requires `ykman`).

- [#161](https://github.com/mike-north/vaultkeeper/pull/161) [`b37bfd7`](https://github.com/mike-north/vaultkeeper/commit/b37bfd701cb094a4ea6106e4bbf8300c3883272b) Thanks [@mike-north](https://github.com/mike-north)! - Breaking (0.x): `@vaultkeeper/wasm`'s `setup()` now requires an explicit executable-trust choice, closing a security-parity gap with the TypeScript `vaultkeeper` library. Versioned as a minor bump under 0.x semver (breaking changes ship as minor bumps while the SDK is pre-1.0).

  Previously the WASM SDK's `setup()` defaulted the executable identity to the `'dev'` sentinel when `executablePath` was omitted, so a bare `vault.setup(name, value)` silently minted an unverified token — the same permissive default that `VaultKeeper.setup()` in the pure-TypeScript library retired. The two SDKs now share the same explicit-choice contract.

  Callers must now provide exactly one of:
  - `executablePath` — the calling executable's real path, bound into the minted token, or
  - `skipTrust: true` — a self-describing, greppable, development-only opt-out that deliberately skips the binding.

  Supplying neither — or both — or the retired `'dev'` sentinel as `executablePath` now throws the new typed `ExecutableTrustRequiredError` (a `VaultError` subclass, exported from the package root) instead of silently minting an unverified token. Its `reason` field is `'missing-choice'`, `'conflicting-choice'`, or `'legacy-dev-sentinel'`, matching the library's `ExecutableTrustRequiredError`.

  **Migration** — every existing `setup()` call must now name a trust choice:

  ```ts
  // Before — unverified by default (silent skip):
  vault.setup('MY_API_KEY', 'my-secret-value')

  // After — bind the calling executable (production):
  vault.setup('MY_API_KEY', 'my-secret-value', { executablePath: process.argv[1] })

  // After — deliberately skip the binding (development/tests only):
  vault.setup('MY_API_KEY', 'my-secret-value', { skipTrust: true })
  ```

  Callers that passed the `'dev'` sentinel as `executablePath` must switch to `skipTrust: true`; the legacy sentinel is now rejected at runtime with `ExecutableTrustRequiredError` (`reason: 'legacy-dev-sentinel'`).

- [#154](https://github.com/mike-north/vaultkeeper/pull/154) [`fc544ae`](https://github.com/mike-north/vaultkeeper/commit/fc544aeb949f5064c9525f356dbe03a35296be25) Thanks [@mike-north](https://github.com/mike-north)! - Fix the WASM SDK's JS host bridge erasing filesystem errno codes: a permission-denied read or delete previously surfaced as a generic `VaultError`, indistinguishable from any other failure, instead of a typed error a caller could branch on.

  `readFile`/`deleteFile`/`fileExists` in the Node host bridge (`createNodeHost`) now reject with a structured `{ message, path, code }` contract that `JsHostPlatform` (the Rust side of the bridge) reads back to build a typed `VaultError::Filesystem`, mirroring the native CLI host's classification: a genuine "does not exist" still resolves to `SecretNotFoundError`, while permission and other errno failures now surface as a new public `FilesystemError` (with `path`, `permission`, and `code` fields — `code` carries the underlying errno, e.g. `EACCES`, when available). Exported from `@vaultkeeper/wasm` alongside the rest of the typed error hierarchy.

- [#85](https://github.com/mike-north/vaultkeeper/pull/85) [`b8262d9`](https://github.com/mike-north/vaultkeeper/commit/b8262d95c8017f0a59f7c8ed9d48f339edb890f3) Thanks [@mike-north](https://github.com/mike-north)! - Stop `authorize()` from returning the raw secret and add typed errors.

  `authorize()` no longer exposes the plaintext secret on its result: the returned
  `claims` no longer carry `val`. The secret is now read through a one-time
  `SecretAccessor` on `result.secret` (`secret.read((value) => ...)`), mirroring the
  `createSecretAccessor` pattern in the TypeScript library — the value is available
  exactly once and is never part of the default return shape.

  The SDK now exports a typed error hierarchy aligned with `VaultError`
  (`SecretNotFoundError`, `InvalidTokenError`, `TokenExpiredError`, `KeyRotatedError`,
  `KeyRevokedError`, `TokenRevokedError`, `UsageLimitExceededError`,
  `RotationInProgressError`, `AccessorConsumedError`), and thrown errors are real
  instances of these classes so `err instanceof VaultError` holds across the ecosystem.

  This is a breaking change to the `authorize()` return shape: code that read
  `result.claims.val` must switch to `result.secret.read(...)`.

- [#178](https://github.com/mike-north/vaultkeeper/pull/178) [`09c48d7`](https://github.com/mike-north/vaultkeeper/commit/09c48d7cb6dddee2e96cf7c0f2061bf9a43503dc) Thanks [@mike-north](https://github.com/mike-north)! - Enforce executable-trust verification in `setup()` when an `executablePath` is supplied.

  Previously, passing `executablePath` bound the raw path into the token's `exe` claim with no hashing and no trust-manifest consultation — a caller that explicitly asked for executable trust got none. `setup()` now hashes the executable and runs trust-on-first-use verification (Sigstore → trust-manifest match → TOFU first-encounter) through the host bridge, binding the verified hash into the `exe` claim, matching the pure-TypeScript `vaultkeeper` library's behavior.
  - A first encounter records the executable's hash under trust-on-first-use. A later `setup()` with a matching hash passes; a changed hash throws the new `IdentityMismatchError` (carrying `previousHash` / `currentHash`) rather than silently re-approving.
  - The first-encounter manifest write is committed only after the token has been minted, so a failed `setup()` never leaves a premature trust record behind.
  - `skipTrust: true` is unchanged — it still opts out of verification and mints a `'dev'`-bound token.

  **Behavior change:** `setup()` is now `async` and returns `Promise<string>` (it performs executable hashing and manifest I/O). Callers must `await` it. Supplying `executablePath` now performs real verification and can throw `IdentityMismatchError`.

- [#203](https://github.com/mike-north/vaultkeeper/pull/203) [`9b3e193`](https://github.com/mike-north/vaultkeeper/commit/9b3e193eed2125d28f381df40ce0be5317e604cc) Thanks [@mike-north](https://github.com/mike-north)! - Enforce the `setup()` executable-trust choice at compile time in `@vaultkeeper/wasm`, matching the TypeScript `vaultkeeper` library. Versioned as a minor bump under 0.x semver (a tightened type contract is a compile break for callers omitting the choice, but ships as a minor while the SDK is pre-1.0).

  Previously `setup()`'s options argument was typed as optional (`options?: SetupOptions`) with all-optional fields, so a two-argument `vault.setup(name, value)` — or `vault.setup(name, value, {})` — type-checked cleanly yet threw `ExecutableTrustRequiredError` (`reason: 'missing-choice'`) at runtime. WASM users got no compile-time protection on the very trust choice the rest of the ecosystem type-enforces.

  `SetupOptions` is now `SetupOptionsBase` (`ttlMinutes` / `useLimit` / `backendType`) intersected with a discriminated union requiring **exactly one** of `executablePath` or `skipTrust: true`, and the options argument is required. As a result these are now compile errors instead of runtime-only failures:

  ```ts
  vault.setup('MY_API_KEY', 'my-secret-value') // missing choice
  vault.setup('MY_API_KEY', 'my-secret-value', {}) // missing choice
  vault.setup('MY_API_KEY', 'my-secret-value', { executablePath: p, skipTrust: true }) // both
  ```

  The valid single-choice forms are unchanged:

  ```ts
  vault.setup('MY_API_KEY', 'my-secret-value', { executablePath: process.argv[1] })
  vault.setup('MY_API_KEY', 'my-secret-value', { skipTrust: true })
  ```

  The runtime `ExecutableTrustRequiredError` remains as a backstop for untyped (plain-JavaScript) callers.

### Patch Changes

- [#205](https://github.com/mike-north/vaultkeeper/pull/205) [`2086c0a`](https://github.com/mike-north/vaultkeeper/commit/2086c0ab38a7aafd0059c95f2e4a21b7bd32d29c) Thanks [@mike-north](https://github.com/mike-north)! - Fix the WASM SDK failing to read a config directory produced by the documented `vaultkeeper config init` flow. `config init` (and the README example) writes `defaults.trustTier` as a bare JSON number (`3`), but the Rust-core config reader behind the SDK required a string-encoded number, so `createVaultKeeper()` threw `VaultError: Failed to parse config` on a CLI-produced config.

  The core config reader now accepts `trustTier` as either a bare number (`3`) or a string-encoded number (`"3"`), and writes the bare-number form — aligning the native CLI output, the TS CLI, the TS library, and the README on one canonical wire form while remaining backward compatible with existing string-form configs. The `tid` claim in JWE tokens is unchanged and keeps its string wire form.

- [#187](https://github.com/mike-north/vaultkeeper/pull/187) [`a822564`](https://github.com/mike-north/vaultkeeper/commit/a8225649de1d9ab062055ef3eab96374cc31e2f9) Thanks [@mike-north](https://github.com/mike-north)! - Ship a per-package `LICENSE` and align docs for signing/verification and packaging.
  - Every published package now carries its own `LICENSE` file and lists `LICENSE` + `README.md` explicitly in its `files` array, so the packaging declaration matches what npm actually ships (previously only a root `LICENSE` existed, which `npm pack` does not include in per-package tarballs). A packaging test now asserts `LICENSE` is present in each tarball.
  - Documented `sign()`'s precondition that the stored secret must be **PEM private-key** material — secrets are stored as strings and `crypto.createPrivateKey()` treats a string as PEM, so raw binary DER must be converted to PEM before storing; a plain-string secret throws `InvalidKeyMaterialError`. Added a distinct example key and a runnable end-to-end `generateKeyPairSync` → store → sign → verify walkthrough, plus `InvalidKeyMaterialError` in the repository README's error table.
  - Scoped the delegated access patterns (`fetch()`/`exec()`/`getSecret()`/`sign()`/`verify()`) explicitly to the TypeScript library and clarified that `@vaultkeeper/wasm`'s `executablePath` is a non-enforcing claim label, unlike this library's TOFU-verified `executablePath`.
  - Added a `getSecret()` code sample, a top-of-README quick-links/TL;DR block, a note that doctor deliberately checks all supported backends' tooling, and a more precise TypeScript-version note that shows the exact known-good consumer `compilerOptions` the CI matrix verifies across TypeScript 5.0.4–7.0.2.

- [#77](https://github.com/mike-north/vaultkeeper/pull/77) [`26c876c`](https://github.com/mike-north/vaultkeeper/commit/26c876c4ba58eff1639cf6e2307f8c01fe5d85bd) Thanks [@mike-north](https://github.com/mike-north)! - Ship a package-specific README.md and `repository`/`homepage`/`bugs` metadata with every published package, so registry consumers get install instructions and a quick start without leaving npm.

- [#112](https://github.com/mike-north/vaultkeeper/pull/112) [`5a8c11d`](https://github.com/mike-north/vaultkeeper/commit/5a8c11dd51ea844eb708de60aed2422fe94de269) Thanks [@mike-north](https://github.com/mike-north)! - Fix a doc comment on `SecretAccessor` that referenced the non-existent `createSecretAccessor` export instead of the real `getSecret()` pattern it mirrors. No behavior change.

- [#135](https://github.com/mike-north/vaultkeeper/pull/135) [`c1a4c0a`](https://github.com/mike-north/vaultkeeper/commit/c1a4c0ac929bc2096d3dfd7d30b7a977f9ddf703) Thanks [@mike-north](https://github.com/mike-north)! - Fix the Rust core's file backend collapsing distinct failure modes into wrong or unstructured errors:
  - `retrieve()` no longer misreports a read failure on an entry that actually exists (e.g. a permission error) as `SecretNotFoundError`. Only a genuine "entry does not exist" maps to `SecretNotFoundError`; other read failures now propagate with their real message instead of the misleading "secret not found".
  - `delete()` no longer collapses a non-not-found delete failure into an opaquely re-wrapped message.
  - Corrupted ciphertext or a failed AES-GCM auth tag on `retrieve()` now throws a new typed `DecryptionError` (with a `path` field), mirroring the `vaultkeeper` library's `DecryptionError`, instead of the untyped catch-all error.

- [#213](https://github.com/mike-north/vaultkeeper/pull/213) [`2e01b05`](https://github.com/mike-north/vaultkeeper/commit/2e01b05c50514f6897bfb5362b5f3901f81e4f48) Thanks [@mike-north](https://github.com/mike-north)! - Fix two trust-manifest integrity gaps in the Rust core's TOFU verify/commit split. `PendingTrust::commit` now reloads the on-disk manifest immediately before saving and re-classifies the staged `(namespace, hash)` entry against the current state: a concurrent write to a **different namespace** is preserved (previously it was silently discarded by saving the verify-time snapshot — mirrors the TypeScript SDK's fix for the same hazard), and a concurrent write of a **different hash for the same namespace** is now refused as a TOFU conflict (`IdentityMismatchError`, nothing written) instead of being silently merged in as a second approved hash.

- [#220](https://github.com/mike-north/vaultkeeper/pull/220) [`e800683`](https://github.com/mike-north/vaultkeeper/commit/e80068344a5ab0483b1cd98e55619c8b8f51b363) Thanks [@mike-north](https://github.com/mike-north)! - Polish setup() editor guidance and CLI/README papercuts.

  **`setup()` compile-error hint.** Both `VaultKeeper.setup()` in the `vaultkeeper` library and `@vaultkeeper/wasm` now carry a TSDoc note that names the exact compile errors a missing trust choice produces (TS2554/TS2345) and the two remedies — add exactly one of `executablePath` or `skipTrust: true` — so hovering the call in-editor explains the fix rather than leaving the bare compiler message. The WASM `setup()` also gains a runnable `@example`.

  **`useLimit` "use" semantics documented.** The README now spells out that `useLimit` bounds calls to `vault.authorize(jwe)`, not downstream delegated `fetch()`/`exec()`/`getSecret()` calls: each `authorize(jwe)` consumes one use, and the resulting `CapabilityToken` can be reused across many delegated calls; only a second `authorize(jwe)` throws `UsageLimitExceededError`.

  **`verify` inline-PEM parsing.** `vaultkeeper verify --public-key`/`--signature` now reject inline PEM material with a clear, actionable usage error (exit 2) instead of node's opaque "argument is ambiguous" — the flags are file-path-only, and the message says so and points at the `--public-key=<path>` escape for a path that legitimately begins with a dash.

  **Unknown-command suggestion.** An unrecognized subcommand now prints an npm/git/cargo-style `Did you mean '<closest>'?` suggestion (e.g. `doctro` → `doctor`) plus a one-line pointer to `vaultkeeper --help` and the docs, giving tarball-only users a discovery path.

  **README Quick Start.** The CLI Quick Start code block now includes an inline `--config-dir`/`VAULTKEEPER_CONFIG_DIR` reminder so a copy-paster gets the isolated-config guidance that was previously only in prose.

- [#196](https://github.com/mike-north/vaultkeeper/pull/196) [`7ee1a61`](https://github.com/mike-north/vaultkeeper/commit/7ee1a61b15a044db2444970adc2c3d7013f5fa47) Thanks [@mike-north](https://github.com/mike-north)! - Type-enforce the `setup()` trust choice, fix the quick-start rebuild footgun, and polish docs and CLI usage errors.

  **`SetupOptions` is now a discriminated union (type-enforced trust XOR).** `VaultKeeper.setup()`'s options argument is required and must carry **exactly one** of `executablePath` (TOFU verification) or `skipTrust: true` (development opt-out). Supplying neither — including a bare `setup('NAME')` or `setup('NAME', {})` — or both is now a **compile-time** error rather than a runtime-only failure; `ExecutableTrustRequiredError` remains the runtime backstop for untyped (plain-JavaScript) callers. `SetupOptionsBase` is exported for the common (non-trust) options. `@vaultkeeper/test-helpers` gains a matching public `TestVaultSetupOptions` type; `TestVault.setup()` keeps its permissive, trust-choice-optional signature (it still defaults to `skipTrust: true`).

  **Quick-start rebuild footgun fixed.** The library quick start no longer steers first-timers to `executablePath: process.argv[1]`, which pins TOFU trust to the compiled entry-file hash and throws `IdentityMismatchError` on the next run after any rebuild. The runnable snippets now use the development-safe `{ skipTrust: true }`, with an inline warning and a clearly-framed production example that binds a **stable** anchor (a released binary or `process.execPath`), plus a cross-reference to Development mode for frequently-rebuilt local callers.

  **Docs and CLI papercuts.** Documented `exec()`'s `[REDACTED]`-by-default output redaction and the `redact: false` opt-out in the library README; clarified that `VaultKeeper.init()` is in-memory and does not write `config.json` (only the CLI `config init` does); clarified that pre-approving a caller is a required first step for non-interactive/CI first `exec` (CLI) versus auto-recorded on first encounter (library); and documented the WASM `doctor()` unscoped required-vs-informational semantics. The CLI now prints a `Usage:` block (and exits 2) for an unknown top-level flag, matching the unknown-command and subcommand-level usage errors.

- [#176](https://github.com/mike-north/vaultkeeper/pull/176) [`f2baa86`](https://github.com/mike-north/vaultkeeper/commit/f2baa86b9f329a5a557f27c5985a3950c351e7b5) Thanks [@mike-north](https://github.com/mike-north)! - Close the `@vaultkeeper/wasm` getting-started and API-reference documentation gaps.
  - The WASM quick start now leads with an ESM-setup callout. `@vaultkeeper/wasm` is ESM-only (no CommonJS fallback), so a copy-paste of the snippet into a default `npm init -y` (CommonJS) project previously failed with `SyntaxError: Cannot use import statement outside a module`. The callout documents adding `"type": "module"` first, so the documented steps now succeed from a fresh project.
  - `SetupOptions.executablePath` JSDoc (and the generated API reference) now states positively that this WASM SDK records the path as a claim label and performs no trust-on-first-use (TOFU) verification — no hashing, manifest check, or throw on a changed/nonexistent path — unlike the TypeScript `vaultkeeper` library's `VaultKeeper.setup()`. Cross-references the behavioral follow-up tracked separately.
  - The `vaultkeeper` README Trust-tiers section now scopes its "requires an explicit executable-trust choice / never silently skips verification" guarantee to the TypeScript library, and notes that `@vaultkeeper/wasm` records `executablePath` as a claim label without running TOFU verification.
  - `SetupOptions.backendType` is now documented as a claim label only (recorded in the token's `bkd` claim) that does not select or route through a functional backend, mirroring the claim-label framing of `executablePath`.

- [#194](https://github.com/mike-north/vaultkeeper/pull/194) [`b2f71bb`](https://github.com/mike-north/vaultkeeper/commit/b2f71bbfad0ee179a3036e17ff50d20da133007e) Thanks [@mike-north](https://github.com/mike-north)! - Guard the WASM SDK's string arguments so a non-string input surfaces a typed, catchable error instead of crashing the process.

  `VaultKeeper` forwarded its arguments straight into WebAssembly with no JS-side type check, so a non-string — a number, a plain object, or (a common mistake) an un-awaited `setup()` Promise — reached wasm-bindgen's string marshaling and aborted the process with an opaque `VaultError: memory access out of bounds` fault. A malformed token _string_ by contrast already yielded a clean `InvalidTokenError`.

  Every wrapper method that forwards a string into WASM now validates the JS type at the boundary, before the value crosses into WebAssembly:
  - `authorize(jwe)` throws `InvalidTokenError` on a non-string `jwe` (joining the malformed-token-string case under one catchable type).
  - `setup(secretName, secretValue)`, `store(id, secret)`, `retrieve(id)`, and `delete(id)` throw `TypeError` on a non-string argument, naming the offending method and parameter.

- [#90](https://github.com/mike-north/vaultkeeper/pull/90) [`741a5fa`](https://github.com/mike-north/vaultkeeper/commit/741a5fafababcfa07d61a21bc853c84beeb60965) Thanks [@mike-north](https://github.com/mike-north)! - Bring `@vaultkeeper/wasm` into the API-report/docs pipeline: `pnpm generate:api-report` now covers the package and `docs/api/` gains generated reference pages for its exports.

- [#206](https://github.com/mike-north/vaultkeeper/pull/206) [`88684f1`](https://github.com/mike-north/vaultkeeper/commit/88684f14bc2128dd907302e4e2e84fc36ee1f78c) Thanks [@mike-north](https://github.com/mike-north)! - Document which WASM SDK methods are async vs. synchronous.

  The `VaultKeeper` surface mixes Promise-returning methods (`setup`, `store`, `retrieve`, `delete`, `doctor`, and the `createVaultKeeper` factory) with synchronous ones (`authorize`, `config`, `rotateKey`, `revokeKey`, `dispose`), which was the root cause of the "forgot to `await` `setup()`" confusion. The README now includes an API methods table marking each method's kind, alongside the existing runtime guard that rejects a Promise passed where a string is expected.

## 0.2.1

### Patch Changes

- [#35](https://github.com/mike-north/vaultkeeper/pull/35) [`5a907e1`](https://github.com/mike-north/vaultkeeper/commit/5a907e138ba336dc7da140170950c93b1c7f43ee) Thanks [@mike-north](https://github.com/mike-north)! - Patch release to verify end-to-end publishing pipeline after release infrastructure fixes (crates.io gating, workspace dependency version sync, cross-platform compatibility)

## 0.2.0

### Minor Changes

- [#29](https://github.com/mike-north/vaultkeeper/pull/29) [`4a5314a`](https://github.com/mike-north/vaultkeeper/commit/4a5314a226ffeaef839b91338c062b14564486fb) Thanks [@mike-north](https://github.com/mike-north)! - Add WASM-backed SDK wrapping the Rust core compiled to WebAssembly. Provides createVaultKeeper factory, doctor checks, JWE token setup/authorize, key rotation/revocation, and secret store/retrieve/delete via a Node.js host platform bridge.
