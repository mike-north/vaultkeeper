# @vaultkeeper/cli

## 0.2.1

### Patch Changes

- Updated dependencies [[`df3ed7b`](https://github.com/mike-north/vaultkeeper/commit/df3ed7bee48c576db0ba266b7a842eb67cd8b6c6)]:
  - vaultkeeper@0.7.1

## 0.2.0

### Minor Changes

- [#89](https://github.com/mike-north/vaultkeeper/pull/89) [`46df0b0`](https://github.com/mike-north/vaultkeeper/commit/46df0b081432a3b14570a2599e27861f7ecc85bc) Thanks [@mike-north](https://github.com/mike-north)! - Make backend selection visible and overridable from the CLI and introspectable from the library.
  - `vaultkeeper config init --backend <type>` now writes a config whose first enabled backend is `<type>`. Valid values are the registered backend types; an unknown value exits 2 and lists the valid types.
  - Any unknown flag on a `config` subcommand (`config init`, `config show`) now exits 2 with an "unknown option" error instead of being silently ignored — a typo can no longer send secrets to an unintended credential store.
  - `config init` output now states which backend was configured and how to change it. `config show` reports the resolved active backend (first enabled).
  - New public `platformNativeBackendType()` reports the OS-native credential store for the current platform (`keychain` on macOS, `dpapi` on Windows, `secret-tool` on Linux, `file` on other platforms) — the store you can opt into with `--backend`.
  - New public `VaultKeeper.activeBackendType` getter exposes the type of the active (first enabled) backend at runtime.

- [#92](https://github.com/mike-north/vaultkeeper/pull/92) [`75685ac`](https://github.com/mike-north/vaultkeeper/commit/75685ac1369870f901a7fdcecd815130d42355be) Thanks [@mike-north](https://github.com/mike-north)! - Add a global `--config-dir <path>` flag / `VAULTKEEPER_CONFIG_DIR` environment variable to the CLI so every command (`store`, `delete`, `exec`, `approve`, `dev-mode`, `doctor`, `config`, `rotate-key`, `revoke-key`) can be pointed at an isolated config directory — the flag wins over the env var, which wins over the platform default. `config init` creates the override directory as needed, and `config show` reports the path it loaded from. The library's `getDefaultConfigDir()` and `loadConfig()` are now public so embedders and the CLI share the same resolution logic. `@vaultkeeper/cli-test-helpers`'s `createCliTestEnv()` gains a `configDirMode` option (`'env'` | `'flag'`) and no longer manipulates the subprocess's `HOME` directory to achieve isolation.

- [#95](https://github.com/mike-north/vaultkeeper/pull/95) [`4ebfa5d`](https://github.com/mike-north/vaultkeeper/commit/4ebfa5d2884da2984fde6736fa6f63dcb6524f06) Thanks [@mike-north](https://github.com/mike-north)! - Uniform CLI exit-code taxonomy (0 success / 1 runtime failure / 2 usage error) applied everywhere: a top-level typo like `vaultkeeper --bogus` now exits 2 with an error instead of silently exiting 0, and an unrecognized flag on `store`, `delete`, `exec`, `approve`, `dev-mode`, or `doctor` now exits 2 instead of a bare fatal error (exit 1).

  `store` (and `delete`, for consistency) now reject an empty or whitespace-only `--name` with exit 2 and the same error style as a missing flag, instead of persisting a near-unreachable secret or surfacing a generic runtime error. Allowed `--name` characters (letters, digits, `.`, `_`, `-`, `/`) are documented in `--help`.

  `exec` now validates that the secret exists before the caller-approval/TTY gate, so `exec --secret <nonexistent> ...` reports a clear `SecretNotFoundError` regardless of TTY, instead of being masked by the generic "requires interactive approval" message. This is backed by a new public `VaultKeeper.secretExists(name)` method — a side-effect-free existence check that never touches the TOFU trust manifest.

  `config init --help` and `config show --help` now print help for that subcommand instead of the parent `config` help. `exec --help` includes a worked `--caller` example.

- [#94](https://github.com/mike-north/vaultkeeper/pull/94) [`0ca9d3f`](https://github.com/mike-north/vaultkeeper/commit/0ca9d3fa5ab7a4bca5a92a8c62904ea279e8bfb3) Thanks [@mike-north](https://github.com/mike-north)! - `doctor` and `config show` now detect an invalid config file instead of silently ignoring it. `doctor` validates the config file (when present) as part of its preflight checks and reports a failing `config` check with the parse/validation error and file path, exiting non-zero. `config show` on invalid JSON now exits non-zero with the parse error (including a line/column location when available) instead of dumping the raw file with exit 0. Every config parse/validation error raised by `loadConfig()` — surfaced through `store`, `delete`, `exec`, `config show`, and `doctor` alike — now includes the config file path, the parse location where available, and a remediation hint naming `vaultkeeper config init`.

  `loadConfig()` now falls back to platform defaults only when the config file is missing (`ENOENT`). A present-but-unreadable file (e.g. a permissions error) is rethrown as a typed `FilesystemError` instead of being silently treated as "no config" — a genuinely broken config was previously invisible to `doctor` and `config show`.

  The "no config file" story is now uniform across `store`, `delete`, `exec`, `config show`, and `doctor`: each falls back to platform defaults and prints a one-line notice naming the resolved backend and `vaultkeeper config init` (e.g. `No config file found; using platform defaults (keychain). Run 'vaultkeeper config init' to persist one.`). Previously `config show` errored with exit 1 on a missing config file while the other commands defaulted silently; `config show` now defaults and reports it like the rest.

  New public `ConfigParseError` (with `path` and `location` fields) is thrown on invalid config JSON. `ConfigValidationError` gains an optional `configFilePath` field. `PreflightCheckStatus` gains an `'invalid'` value, and `RunDoctorOptions` gains an optional `configDir` field that lets `runDoctor`/`VaultKeeper.doctor()` load and validate the config itself.

- [#121](https://github.com/mike-north/vaultkeeper/pull/121) [`7c8ab85`](https://github.com/mike-north/vaultkeeper/commit/7c8ab857859049fce5d9e1518d13a2b126293540) Thanks [@mike-north](https://github.com/mike-north)! - Scope `doctor` to the active/configured backend so a fresh install no longer looks broken. Previously `doctor` rendered every non-`'ok'` check with a failing `✗` icon, including plugin-backend tools (`ykman`, `op`) that weren't configured — on the post-#98 `file`-default install, this meant the very first `doctor` run showed a failing check for a YubiKey/1Password tool the user never opted into.

  `PreflightResult.checks` entries are now `ScopedPreflightCheck` (a `PreflightCheck` plus `required: boolean`), reflecting whether each dependency is required for the active/configured backend(s). The CLI only renders the `✗` icon for checks that are both required and failing; unmet optional checks still surface, without the failure icon, in the `Warnings` section. Opt-in backends still get their dependency checks promoted to required when configured (e.g. `--backend yubikey` requires `ykman`).

- [#86](https://github.com/mike-north/vaultkeeper/pull/86) [`be28555`](https://github.com/mike-north/vaultkeeper/commit/be28555c0e530ed2f33075900b2395db93f5464d) Thanks [@mike-north](https://github.com/mike-north)! - `vaultkeeper exec` can now run non-interactively. A caller already recorded in the TOFU trust manifest (via `approve` or a prior approval) runs without any prompt on a TTY or not. A new explicit opt-in — the `--yes` flag and the `VAULTKEEPER_YES=1` environment variable — approves an untrusted caller for a single invocation without prompting, recording the approval the same way an interactive `y` would. Without trust and without `--yes`, an untrusted caller on non-TTY stdin still fails, but the error now tells you exactly how to proceed (`vaultkeeper approve --script <caller>` or `--yes`). `exec --help` documents the TTY requirement and both escape hatches, and the README gains a "Running in CI" note. A caller whose contents changed since approval is never auto-approved by `--yes`; it must be re-approved with `vaultkeeper approve`.

- [#210](https://github.com/mike-north/vaultkeeper/pull/210) [`38fafb5`](https://github.com/mike-north/vaultkeeper/commit/38fafb5bc661d360c96d2b79462a556a0dcd73ba) Thanks [@mike-north](https://github.com/mike-north)! - Add a backend `presencePerUse` capability and the ability to require it for an operation.

  `presencePerUse` means "every operation with a key in this backend forces a distinct, fresh physical human action, and can never be satisfied from a cached or session-unlocked state." vaultkeeper is now the single place that knows this per configured backend instance and enforces it, so consumers never have to reason about YubiKey touch policies or 1Password per-access tricks themselves.

  Library:
  - New `PresenceCapableBackend` extension interface (`getCapabilities(): Promise<BackendCapabilities>`) — mirrors `ListableBackend`/`SigningBackend`; it is not a required member of `SecretBackend`. `BackendCapabilities` is `{ presencePerUse: boolean }` and is open to extension.
  - New `getBackendCapabilities(backend)` helper and `isPresenceCapableBackend(backend)` guard. A backend that does not implement the interface reports `{ presencePerUse: false }` — an unknown backend never silently claims presence. The capability reflects the configured instance (a YubiKey slot's touch policy, 1Password's access mode), never a hardcoded per-type answer.
  - New `VaultKeeper.getActiveBackendCapabilities()` introspection method.
  - New `requirePresencePerUse?: boolean` option on the shared access path (`store`, `delete`, `setup`, `sign`). Enforcement is queried fresh on every call and refuses before any credential/session/device is touched when unsatisfied; when capable, the operation forces a fresh action for that specific call. Presence-gated signing performs a fresh backend `signWithKey` round-trip per call, so no cached key material can satisfy it.
  - Enforcement is **operation-aware and fail-closed** via `BackendCapabilities.presenceEnforcedOperations` (a list of `PresenceOperation`; omitted means all operations). A backend that forces presence for only some operations refuses a flagged uncovered operation with `NotCapableError` rather than passing without a fresh action. 1Password `per-access` forces presence for reads only (`store`/`delete` route through the cached session client), so a flagged `store`/`delete` on 1Password is correctly refused; a YubiKey touch slot covers every operation.
  - New typed errors (all extend `VaultError`, machine-readable fields, exported): `NotCapableError { backendType, capability }`, `PresenceDeclinedError { backendType }`, `PresenceTimeoutError { backendType, timeoutMs }`.

  CLI:
  - New `vaultkeeper backend capabilities [--json]` command lists each registered backend as `{ type, displayName, presencePerUse }` (a flat array with `--json`, human-readable text otherwise).
  - New per-command `--require-presence-per-use` flag on `store`, `delete`, `sign`, and `exec` (never global, never on `verify`). With `exec`, a cached token is never reused under the flag.

- [#108](https://github.com/mike-north/vaultkeeper/pull/108) [`5958996`](https://github.com/mike-north/vaultkeeper/commit/5958996c86094ce49116154924bf97ed05f14328) Thanks [@mike-north](https://github.com/mike-north)! - Make the zero-config default backend safe: the shortest documented getting-started path can no longer silently write a secret to your real OS credential store.
  - With no config file present, a bare `VaultKeeper.init()` — and `vaultkeeper config init` with no `--backend` — now resolves to the portable, self-contained `file` backend on **every** platform, including macOS and Windows. Previously it targeted the OS-native credential store (macOS Keychain, Windows DPAPI), so copy-pasting the first documented example could store a secret in the real login keychain before the user knew backends existed.
  - The platform-native store stays fully supported as an explicit opt-in: `vaultkeeper config init --backend keychain` / `--backend dpapi`, or an explicit config.
  - New public `defaultBackendType()` returns the zero-config default (`'file'`) on every platform. The former `platformDefaultBackendType()` is renamed to `platformNativeBackendType()` — it never was the zero-config default and now reads as what it is: the OS-native store you can opt into.
  - The `doctor` / `store` (and `delete` / `exec` / `config show`) "no config file" advisory now names the `file` default and spells out the remediation as `vaultkeeper config init --backend file`, never a bare `config init`, so following the hint verbatim persists exactly the backend that was in effect.

  Note: this changes only the TypeScript library and Node.js CLI. The native Rust CLI's zero-config default is unchanged for now.

- [#159](https://github.com/mike-north/vaultkeeper/pull/159) [`68d8b9c`](https://github.com/mike-north/vaultkeeper/commit/68d8b9cbc95b31086e4e4a94f6cf73ef279fff4d) Thanks [@mike-north](https://github.com/mike-north)! - Make signing and verification of arbitrary challenges a first-class, CLI-exposed primitive with a stable, third-party-verifiable signature format.
  - New CLI commands (`@vaultkeeper/cli`): `key create --name <n> --type ed25519` provisions a signing keypair (unknown `--type` exits 2, never a silent default); `key export --name <n>` prints the SPKI PEM public key; `sign --name <n>` reads all of stdin and writes exactly the detached signature to stdout (pipeline-safe; status on stderr); `verify --public-key <pem> --signature <sig>` verifies a detached signature fully offline (no config, backend, or key store). `verify` adds exit code `3` for a signature that did not verify — a deliberate, documented exception to the `0/1/2` taxonomy so scripts can tell a bad signature from a broken tool.
  - Signatures are detached-payload Compact JWS (RFC 7515 §7.2.2 + RFC 7797 `b64:false`, `crit:["b64"]`, `alg` EdDSA/Ed25519). Any standards-compliant JOSE library can verify a signature given the payload and the public key.
  - Signing keys are a distinct resource from secrets: a new backend signing contract (`generateSigningKey`/`getPublicKey`/`signWithKey`, mirroring `ListableBackend`) keeps private key material backend-side. It never flows through `store()`/`retrieve()`/`fetch()`/`exec()` or a capability token's claims, and `fetch()`/`exec()`/`getSecret()` reject a signing-key token outright. The `file` backend implements the contract; backends that do not fail with a typed `SigningNotSupportedError`.
  - Breaking (library): the `SignRequest`/`SignResult`/`VerifyRequest` shapes and `VaultKeeper.sign()`/`VaultKeeper.verify()` are reshaped to the JWS contract. `sign()` now takes a signing-key capability token from the new `authorizeSigningKey()` and returns `{ jws }`; `verify()` is async and takes `{ payload, jws, publicKey }`. New public API: `createSigningKey()`, `exportPublicKey()`, `authorizeSigningKey()`, `SigningBackend`/`isSigningBackend`, `SigningAlgorithm`, `SigningPublicKey`, and the `SigningKeyNotFoundError`/`SigningNotSupportedError` typed errors.

### Patch Changes

- [#231](https://github.com/mike-north/vaultkeeper/pull/231) [`f863dfc`](https://github.com/mike-north/vaultkeeper/commit/f863dfcbf49cfdb9700cd3438388a2218155d5f1) Thanks [@mike-north](https://github.com/mike-north)! - Wrap config-directory CREATION failures in a typed `FilesystemError` instead of leaking a raw Node error.

  `vaultkeeper config init` (and the first `store`, which persists key state before writing any secret) against a config directory whose parent is read-only previously aborted with the raw, unwrapped `Error: EACCES: permission denied, mkdir '<path>'` — no error class, no plain-English description, no fix hint. Only the config-directory READ paths had been wrapped previously.

  The directory-creation path now surfaces a typed `FilesystemError` (with the path and the underlying errno code) rendered through the CLI's error formatter with directory-specific wording and a parent-directory fix hint (check that the parent directory is writable, or choose a writable location with `--config-dir`). The raw `EACCES`/`mkdir` errno text no longer reaches the user, and the command still exits non-zero. The key-state write path is likewise wrapped.

- [#158](https://github.com/mike-north/vaultkeeper/pull/158) [`a93ac5e`](https://github.com/mike-north/vaultkeeper/commit/a93ac5e4dc044031acff667c960c1faaa28abfdc) Thanks [@mike-north](https://github.com/mike-north)! - Fix two CLI config-error remediation gaps left over from #129:
  - An unreadable `config.json` (e.g. `EACCES`/`EPERM` from a root-owned file or `chmod 000`) now gets a CLI-native message naming the file path and suggesting a permissions check — it no longer falls through to the library's "install `@vaultkeeper/cli`" text, and it never recommends `config init --force` (which would hit the same permission error trying to write the replacement file).
  - A structurally invalid `config.json` now names the failing field again (e.g. ``The config at `<path>` is invalid (`version`) — run `vaultkeeper config init --force` to overwrite it.``) — #129 dropped this detail with no replacement.

- [#188](https://github.com/mike-north/vaultkeeper/pull/188) [`06596e2`](https://github.com/mike-north/vaultkeeper/commit/06596e2b79f3fc6dc66e94efd5cccd3b36053081) Thanks [@mike-north](https://github.com/mike-north)! - Route the shared config-file presence check through the typed `FilesystemError` path, and fix three CLI message papercuts.
  - `store`, `config show`, `delete`, and `exec` against a config directory the process cannot read (e.g. `chmod 000`) no longer leak a raw Node `EACCES: permission denied, access '.../config.json'` string. They now render the same typed `FilesystemError` with a permissions remediation that `doctor` already produced — a human message naming the file and pointing at the file's permissions, with a non-zero exit.
  - `delete`'s "secret not found" message no longer tells the user to run `store` to _create_ the secret they are trying to delete. It keeps the shared diagnostic line but gives a neutral, delete-appropriate hint. `exec` (an access path) still suggests creating the secret.
  - `exec`'s required-flags validation error now includes the standard `Usage:` line, matching every sibling validation error (exit code 2).
  - `vaultkeeper approve --help` now states that `approve` is a required first step for a new caller in non-interactive/CI contexts (non-TTY stdin), where there is no prompt to grant trust — not merely an optional prompt-avoidance convenience.

- [#160](https://github.com/mike-north/vaultkeeper/pull/160) [`90a4127`](https://github.com/mike-north/vaultkeeper/commit/90a412791bdd3436c0c8c0e61179a5df1da664d5) Thanks [@mike-north](https://github.com/mike-north)! - Fixed CLI error output so recovery hints repair the file they diagnose and read cleanly.
  - The invalid-config recovery hint now carries an explicit `--config-dir '<dir>'` whenever a non-default config directory is active (from `--config-dir` or `VAULTKEEPER_CONFIG_DIR`), so the copy-pasted `vaultkeeper config init --force …` command repairs the exact diagnosed file instead of writing a fresh config to the platform default and leaving the corrupt file untouched. The default-directory case stays bare (no path is leaked). A new `getPlatformDefaultConfigDir()` export computes the machine default independent of `VAULTKEEPER_CONFIG_DIR`, so a directory that came only from the environment variable still gets an explicit flag (a fresh shell running the pasted command won't have that variable set); `getDefaultConfigDir()` now delegates to it.
  - `FilesystemError` now renders a human message from its typed `path`/`permission` fields — plainly stating whether the file is missing or permission-denied, with a suggested next step — instead of leaking the raw Node `ENOENT: … open '<path>'` text. The typed class and its fields are unchanged.
  - `doctor` prints the config remediation exactly once (under "Next steps") instead of duplicating it inline on the failing config check.

- [#140](https://github.com/mike-north/vaultkeeper/pull/140) [`94db84c`](https://github.com/mike-north/vaultkeeper/commit/94db84c9b99d6221c8e0ae1121d9d48bf1e62d4d) Thanks [@mike-north](https://github.com/mike-north)! - Fix CLI error-experience papercuts:
  - `exec` and `delete` now report an identical "secret not found" message (`Secret "<name>" not found in the "<backend>" backend.`) with a recovery hint (`Run \`vaultkeeper store --name <name>\` to create it.`) — previously each surfaced different wording and neither pointed at a fix.
  - `store` with empty stdin now exits 2 (usage error) instead of 1, consistent with a missing or empty `--name` — both mean "no usable input was given."
  - The library's `ConfigValidationError` message now separates the validation diagnosis from the remediation hint with a period instead of running them together with no punctuation.

- [#109](https://github.com/mike-north/vaultkeeper/pull/109) [`f24de45`](https://github.com/mike-north/vaultkeeper/commit/f24de45dc1f67ec513b8155b86b11102b14fb31f) Thanks [@mike-north](https://github.com/mike-north)! - Document the CLI's exit-code contract (0 success / 1 runtime error / 2 usage error, with an example
  of each) and the `--config-dir` flag / `VAULTKEEPER_CONFIG_DIR` env var in the CLI README. Note in
  the library README that consumers need `"type": "module"` (vaultkeeper is ESM-only) and that
  `useLimit` defaults to unlimited (`null`) when omitted from `setup()` options.

  `RotationInProgressError`'s message now includes a next step — run `vaultkeeper revoke-key` (or
  call `revokeKey()`) to invalidate the previous key immediately, or wait for the grace period to
  elapse — matching the actionable-remediation style of the other domain errors.

- [#129](https://github.com/mike-north/vaultkeeper/pull/129) [`db8936e`](https://github.com/mike-north/vaultkeeper/commit/db8936e0c4a6a88755e0de3af72e7c10511115bd) Thanks [@mike-north](https://github.com/mike-north)! - Fixed the CLI printing the library's "install @vaultkeeper/cli" remediation when it hit an invalid config (`ConfigParseError`/`ConfigValidationError`) — a user already running this CLI was told to install a CLI they already had. The CLI now prints its own remediation naming the file path and the actual recovery command: "The config at `<path>` is invalid — run `vaultkeeper config init --force` to overwrite it." The library's own message (used by JS-API consumers) is unchanged.

- [#226](https://github.com/mike-north/vaultkeeper/pull/226) [`eec6581`](https://github.com/mike-north/vaultkeeper/commit/eec658100b7728d76a918a2fa59b870e74315560) Thanks [@mike-north](https://github.com/mike-north)! - Fixed the CLI README's sign/verify walkthrough: `sign` and `verify` now both read the challenge via `printf '%s'`, so each sees byte-identical stdin — the previous here-string form appended a trailing newline, making the documented example fail verification with exit 3. Shipped READMEs' runnable examples are now exercised by a CI example-fence check so a documented command sequence that stops working fails the build.

- [#206](https://github.com/mike-north/vaultkeeper/pull/206) [`88684f1`](https://github.com/mike-north/vaultkeeper/commit/88684f14bc2128dd907302e4e2e84fc36ee1f78c) Thanks [@mike-north](https://github.com/mike-north)! - Make `--version` discoverable and accept the commonly-guessed `-v`.

  `vaultkeeper --version` already worked, but the top-level `--help` "Global options" block listed only `--config-dir`, so the version flag was findable only by guessing, and `-v` errored as an unknown flag. `--help` now lists `--version` (and `-h, --help`) under Global options, and `-v` is wired to the same version output as `-V`.

  A bare `vaultkeeper` invocation with no arguments now renders that same full help on stdout and exits `0` — it prints the identical text `--help` does, so it is a help request, not a usage error. Genuine misuse (unknown command/flag, missing required argument, empty-stdin `store`) still exits `2`.

- [#105](https://github.com/mike-north/vaultkeeper/pull/105) [`7f9da7a`](https://github.com/mike-north/vaultkeeper/commit/7f9da7a65c3f50bada97d7e0bb6a21770f9a9d2c) Thanks [@mike-north](https://github.com/mike-north)! - Add a supported recovery path for a corrupt or unreadable `config.json`.
  - `vaultkeeper config init --force` now overwrites an existing config file, including one that's present-but-unparseable. `config init` without `--force` keeps its current non-destructive refusal, and now points at `config init --force` in its refusal message. `--force` composes with `--backend` (e.g. `config init --force --backend file`).
  - `ConfigParseError` (and the other `loadConfig` errors sharing its remediation hint) now names `vaultkeeper config init --force` instead of `vaultkeeper config init` — the previous hint sent users to a command that provably failed in the exact state that produced the error.

- [#126](https://github.com/mike-north/vaultkeeper/pull/126) [`cfcd61b`](https://github.com/mike-north/vaultkeeper/commit/cfcd61bce6da0e180000f15d9676218b58fc60dd) Thanks [@mike-north](https://github.com/mike-north)! - Fix `dev-mode` invalid-action misdiagnosis and audit `config.ts`/the file backend for plain `Error` throws.
  - `vaultkeeper dev-mode <action> --script <path>` now distinguishes an invalid action from missing args: an unrecognized action (e.g. `banana`) emits `unknown action "<x>" (expected "enable" or "disable")` (exit 2), while `missing action or --script flag` is reserved for genuinely absent arguments.
  - The encrypted-file secret backend (`FileBackend`) now surfaces `EACCES`/permission failures reading, writing, or deleting a secret entry as a typed `FilesystemError` instead of the raw Node.js error.
  - Added a new `DecryptionError` (extends `VaultError`) for when a stored secret entry fails to decrypt (corrupted ciphertext or a failed AES-GCM auth tag check) — previously thrown as a plain `Error`.

- [#187](https://github.com/mike-north/vaultkeeper/pull/187) [`a822564`](https://github.com/mike-north/vaultkeeper/commit/a8225649de1d9ab062055ef3eab96374cc31e2f9) Thanks [@mike-north](https://github.com/mike-north)! - Ship a per-package `LICENSE` and align docs for signing/verification and packaging.
  - Every published package now carries its own `LICENSE` file and lists `LICENSE` + `README.md` explicitly in its `files` array, so the packaging declaration matches what npm actually ships (previously only a root `LICENSE` existed, which `npm pack` does not include in per-package tarballs). A packaging test now asserts `LICENSE` is present in each tarball.
  - Documented `sign()`'s precondition that the stored secret must be **PEM private-key** material — secrets are stored as strings and `crypto.createPrivateKey()` treats a string as PEM, so raw binary DER must be converted to PEM before storing; a plain-string secret throws `InvalidKeyMaterialError`. Added a distinct example key and a runnable end-to-end `generateKeyPairSync` → store → sign → verify walkthrough, plus `InvalidKeyMaterialError` in the repository README's error table.
  - Scoped the delegated access patterns (`fetch()`/`exec()`/`getSecret()`/`sign()`/`verify()`) explicitly to the TypeScript library and clarified that `@vaultkeeper/wasm`'s `executablePath` is a non-enforcing claim label, unlike this library's TOFU-verified `executablePath`.
  - Added a `getSecret()` code sample, a top-of-README quick-links/TL;DR block, a note that doctor deliberately checks all supported backends' tooling, and a more precise TypeScript-version note that shows the exact known-good consumer `compilerOptions` the CI matrix verifies across TypeScript 5.0.4–7.0.2.

- [#145](https://github.com/mike-north/vaultkeeper/pull/145) [`f5edcd9`](https://github.com/mike-north/vaultkeeper/commit/f5edcd9ed0ca51b2f86b61db7701fa3ced46e031) Thanks [@mike-north](https://github.com/mike-north)! - Give the doctor `config` preflight check structured error context so the CLI can render a CLI-native remediation instead of the library's install text.
  - The public `PreflightCheck` shape gains an optional `error` field (`PreflightCheckError`: `kind` + `configPath` + optional parse `location`) carrying remediation-free, machine-readable context when the `config` check fails on a present-but-invalid config file. A consumer can build its own audience-appropriate remediation from these fields instead of parsing the human-readable `reason` prose.
  - `vaultkeeper doctor` run against a corrupt or invalid config now shows the CLI-native remediation (config path + `vaultkeeper config init --force`), wording-consistent with every other command, and no longer tells a user already running the CLI to "install @vaultkeeper/cli". The library's own `reason` text is unchanged for library consumers.

- [#206](https://github.com/mike-north/vaultkeeper/pull/206) [`88684f1`](https://github.com/mike-north/vaultkeeper/commit/88684f14bc2128dd907302e4e2e84fc36ee1f78c) Thanks [@mike-north](https://github.com/mike-north)! - Surface the offending field in `doctor`'s remediation for a schema-invalid config.

  For a config that parses as JSON but fails schema validation (e.g. `backends: []`), `doctor`'s Next-steps previously said only that the config was invalid, omitting the field-level reason it gives for JSON-parse errors (which name the line/column). The `PreflightCheckError` structured context now carries the offending `field` for a `config-validation` failure — the validation analogue of a parse failure's `location` — so `doctor` renders it (e.g. "is invalid (`backends`)"), matching the wording every other command already used. No `reason` prose is parsed to do this.

- [#177](https://github.com/mike-north/vaultkeeper/pull/177) [`16f67a9`](https://github.com/mike-north/vaultkeeper/commit/16f67a90c223b1fdab9785f777964d12f71b2b37) Thanks [@mike-north](https://github.com/mike-north)! - Render an unreadable config directory as a failing doctor check instead of a raw crash.
  - `vaultkeeper doctor` run against a config directory the process cannot read (e.g. a `chmod 000` directory, so reading `config.json` inside it fails with `EACCES`/`EPERM`) previously aborted with a raw Node `Error: EACCES: permission denied, access '.../config.json'` — no typed class, no fix hint, and no checks rendered at all. It now surfaces the read failure as a failing `config` check (just like a parse or validation failure), keeps rendering the other checks, prints a permissions-oriented remediation under "Next steps", and exits non-zero. The raw errno string no longer leaks to the user.
  - The public `PreflightCheckErrorKind` gains a `'config-read'` member, and `PreflightCheckError` gains an optional `code` field carrying the underlying errno (e.g. `EACCES`), so a consumer can build a permissions-specific remediation. `config init --force` is deliberately not suggested for this failure — it cannot repair a config the process cannot read.

- [#221](https://github.com/mike-north/vaultkeeper/pull/221) [`2705b3a`](https://github.com/mike-north/vaultkeeper/commit/2705b3ad33ed0c2036d54b1eabbb066ebf3355c1) Thanks [@mike-north](https://github.com/mike-north)! - Validate `backends[].type` against the registered backends when loading a config, closing a gap where `doctor` reported a false "System ready." for a config naming a backend that does not exist.
  - Config validation (`loadConfig`, `validateConfig`) now rejects a `backends[].type` that names no registered backend. A config with an unknown type parses as valid JSON and is structurally valid, but the next real command would throw `BackendUnavailableError` at backend-creation time — so `doctor` reporting all-clear undermined the diagnostic the CLI's own corrupted-config recovery points users at.
  - `doctor`'s config check now FAILS (red, exit non-zero) for an unknown backend type and names both the offending type and the valid options — the same guidance the runtime `BackendUnavailableError` gives — instead of silently passing.
  - New public `UnknownBackendTypeError` (a `ConfigValidationError` subclass) carries the offending `backendType` and the `knownTypes`. The `doctor` preflight result gains a `config-unknown-backend` error kind carrying `backendType` and `knownBackendTypes`, so a consumer can render the valid-types guidance without parsing prose.
  - The valid set is read from the backend registry (including any custom backends a consumer registered), not a hardcoded list.

- [#195](https://github.com/mike-north/vaultkeeper/pull/195) [`c7f0068`](https://github.com/mike-north/vaultkeeper/commit/c7f0068145e4b8f7526a3436864ea26e337112fb) Thanks [@mike-north](https://github.com/mike-north)! - Redact injected secrets from library `exec()` output, and give the CLI a typed error when a wrapped command cannot be spawned.
  - `VaultKeeper.exec()` now redacts every injected secret value from the captured `stdout`/`stderr` before returning, replacing each occurrence with `[REDACTED]`. This upholds the documented guarantee that the raw secret never appears in the return value, even when the spawned command echoes it. Multi-secret (`{{secret:name}}`) injections redact all injected values. Pass the new `ExecRequest.redact: false` to opt out and receive raw output. The redaction logic is shared with the CLI's streaming `--no-redact` path via the new public `redactSecrets` helper, so the two surfaces cannot drift.
  - The CLI `exec` command now maps a spawn failure of the wrapped command (`ENOENT` for a nonexistent command, `EACCES` for a non-executable file) to a typed `ExecError` with remediation, rendered through the CLI's typed-error formatter, instead of leaking a bare `Error: spawn <path> ENOENT`.

- [#78](https://github.com/mike-north/vaultkeeper/pull/78) [`414bb05`](https://github.com/mike-north/vaultkeeper/commit/414bb0512743b454359d12750fb69d969cb9b4c3) Thanks [@mike-north](https://github.com/mike-north)! - Honor `BackendConfig.path` for file-based backends. Previously the documented `path` option was validated and then silently ignored: secrets always landed in the hardcoded `$HOME/.vaultkeeper/<backend>` location. The `file`, `dpapi`, and `yubikey` backends now store, retrieve, and delete secrets under the configured directory (created on demand) when `path` is set, falling back to the default location when it is not. The CLI `store` and `delete` commands inherit the fix by routing through `VaultKeeper`, which resolves the first enabled backend from config and forwards that backend's configuration.

  Config validation now rejects a whitespace-only `path` (e.g. `" "`) with the new `ConfigValidationError`, instead of silently treating it as a real storage directory.

- [#77](https://github.com/mike-north/vaultkeeper/pull/77) [`26c876c`](https://github.com/mike-north/vaultkeeper/commit/26c876c4ba58eff1639cf6e2307f8c01fe5d85bd) Thanks [@mike-north](https://github.com/mike-north)! - Ship a package-specific README.md and `repository`/`homepage`/`bugs` metadata with every published package, so registry consumers get install instructions and a quick start without leaving npm.

- [#111](https://github.com/mike-north/vaultkeeper/pull/111) [`ebfcd1d`](https://github.com/mike-north/vaultkeeper/commit/ebfcd1ddfa33c62e671f185d5ebcd4461bb1c80d) Thanks [@mike-north](https://github.com/mike-north)! - Make the packaged READMEs self-contained: `vaultkeeper` and `@vaultkeeper/cli` now include a
  minimal, safe-by-default (`file` backend) example `VaultConfig`/config JSON, plus inline
  explanations of key rotation grace periods, the `trustTier` policy label, and the
  trust-on-first-use (TOFU) check that `exec` reports on every run — so the golden path no longer
  depends on fetching the unshipped repository README.

- [#93](https://github.com/mike-north/vaultkeeper/pull/93) [`8124067`](https://github.com/mike-north/vaultkeeper/commit/81240672a37af315814c4bfda736ae7e339d8259) Thanks [@mike-north](https://github.com/mike-north)! - Persist key material across processes so cached tokens and the rotation grace period work between CLI invocations.
  - `KeyManager` encryption keys are now persisted under the config directory, encrypted at rest with AES-256-GCM under an owner-only (`0600`) wrapping key — reusing the same authenticated-cipher primitives as the file backend. Persistence is active only when `VaultKeeper` loads its configuration from disk (no injected `config`/`backend`); instances built with an injected `config` or `backend` keep keys in memory, so tests and embedders stay hermetic.
  - A JWE minted by one process is now authorizable by a later process within its validity window: its `kid` still resolves after the minting process exits. Previously every process generated fresh keys, so a cached token always failed with `KeyRevokedError`.
  - `vaultkeeper exec --cache` now genuinely reuses a cached token on a second run by the same trusted caller — without re-minting and without the misleading "Cached token expired" message. Cached tokens are reusable until they expire (the secret's TTL) or the key is rotated/revoked, after which `exec` transparently mints a fresh one.
  - The cached-token path no longer collapses every authorization failure into a generic "expired" message. Each failure now surfaces its actual cause (e.g. `KeyRevokedError`, `TokenExpiredError`).
  - The rotation grace-period guard now survives across processes: running `rotate-key` twice while the previous key is still in its grace period fails the second time with `RotationInProgressError` (non-zero exit) instead of silently rotating again.

- [#164](https://github.com/mike-north/vaultkeeper/pull/164) [`ce43052`](https://github.com/mike-north/vaultkeeper/commit/ce43052c9843eb4965e20a8fdad969b8de1858b2) Thanks [@mike-north](https://github.com/mike-north)! - Complete the plain-`Error` audit (issues #115/#126 covered `config.ts` and the file backend): every remaining `throw new Error(...)` in product source now throws a typed error instead.
  - `vaultkeeper`: `util/at-rest.ts` and `backend/yubikey-backend.ts`'s encrypted-envelope decoding now throw `DecryptionError` (malformed envelope, unsupported/legacy file version, or a failed AES-GCM auth tag check) instead of a plain `Error`. `util/platform.ts`'s `currentPlatform()`, `backend/one-password-constants.ts`'s `getIntegrationVersion()`, and `yubikey-backend.ts`'s YubiKey HMAC response validation now throw `SetupError`. `util/exec.ts`'s `execCommand`/`execCommandFull` and the YubiKey `ykman` challenge-response call now throw `ExecError`. `OnePasswordBackend`'s constructor validation (mutually exclusive `accessMode`/`serviceAccountToken`/`account` options) now throws `ConfigValidationError`, and its per-access worker crash/spawn-failure paths now throw `BackendUnavailableError`. No new public error classes or fields were added — every site reuses an existing `VaultError` subclass.
  - `@vaultkeeper/cli`: the non-interactive-approval-required error (in both `approval.ts`'s `promptApproval` and `commands/exec.ts`'s trust gate) now throws a new internal `NonInteractiveApprovalError` (not part of the public API, matching the existing internal `ConfigDirFlagError` pattern) instead of a plain `Error`.

  A new repo-wide guard test (`no-plain-error.test.ts` in both packages) scans every source file under `src/` and fails if a plain `Error` construction (`throw`/`reject`) reappears.

- [#175](https://github.com/mike-north/vaultkeeper/pull/175) [`f20ea5a`](https://github.com/mike-north/vaultkeeper/commit/f20ea5a1aeded6fbdeaf0a937623737f5bc9c756) Thanks [@mike-north](https://github.com/mike-north)! - Round out the shipped package docs so a reader offline (registry-only, air-gapped) can find everything without the GitHub URL:
  - `vaultkeeper` README: new "Multiple secrets in one request" section documenting `SecretTokenMap` and the `{{secret:name}}` placeholder for injecting several secrets into one `fetch()`/`exec()` call; a runnable inline `exec()` example (secret injected via `env`); a complete error-types table covering all `VaultError` subclasses; a full `VaultConfig`/`BackendConfig` field reference; and a "Doctor / preflight checks" section explaining required-vs-informational checks and that a plugin checkmark means "binary detected on PATH", not "backend active".
  - `vaultkeeper` README: `verify()` now notes that the disallowed-algorithm throw does not apply to Ed25519/Ed448 keys (the algorithm override is ignored). The "Testing against this library" section notes `@vaultkeeper/test-helpers` belongs in `devDependencies` and warns that the real `VaultKeeper.setup()` always requires `executablePath` or `skipTrust`.
  - `@vaultkeeper/test-helpers` README: strengthened the warning that the test-only zero-arg `setup()` default does not carry over to the real `VaultKeeper.setup()`.
  - `@vaultkeeper/cli` README: new "Doctor / preflight checks" section on checkmark semantics — plugin checks (`op`/`ykman`) are informational when their backend isn't enabled, but enabling the `1password`/`yubikey` backend promotes its tool check to required; points at the now-self-contained library README for the full error hierarchy and config reference.

- [#119](https://github.com/mike-north/vaultkeeper/pull/119) [`0c1daef`](https://github.com/mike-north/vaultkeeper/commit/0c1daef0466f23cf015d53f201f291029919951e) Thanks [@mike-north](https://github.com/mike-north)! - Close doc gaps left over from the shipped-README audit:
  - `vaultkeeper`'s and `@vaultkeeper/cli`'s README `exec` examples now mention the default `[REDACTED]` output redaction and the `--no-redact` escape hatch inline.
  - The `vaultkeeper` package README now inlines a development-mode explanation, a `sign()`/`verify()` example, and a brief error-hierarchy summary instead of deferring them solely to the unshipped repository README; `@vaultkeeper/cli`'s README gets an inline development-mode explanation too.
  - States a supported TypeScript version (5.x) in both READMEs, and documents a `require()`/CommonJS quick-start variant alongside the existing ESM one.
  - `verify()`'s JSDoc now calls out that it is synchronous and throws immediately (not via a rejected `Promise`) for a disallowed algorithm.
  - Adds a `./package.json` subpath to `vaultkeeper`'s `exports` map.

- [#220](https://github.com/mike-north/vaultkeeper/pull/220) [`e800683`](https://github.com/mike-north/vaultkeeper/commit/e80068344a5ab0483b1cd98e55619c8b8f51b363) Thanks [@mike-north](https://github.com/mike-north)! - Polish setup() editor guidance and CLI/README papercuts.

  **`setup()` compile-error hint.** Both `VaultKeeper.setup()` in the `vaultkeeper` library and `@vaultkeeper/wasm` now carry a TSDoc note that names the exact compile errors a missing trust choice produces (TS2554/TS2345) and the two remedies — add exactly one of `executablePath` or `skipTrust: true` — so hovering the call in-editor explains the fix rather than leaving the bare compiler message. The WASM `setup()` also gains a runnable `@example`.

  **`useLimit` "use" semantics documented.** The README now spells out that `useLimit` bounds calls to `vault.authorize(jwe)`, not downstream delegated `fetch()`/`exec()`/`getSecret()` calls: each `authorize(jwe)` consumes one use, and the resulting `CapabilityToken` can be reused across many delegated calls; only a second `authorize(jwe)` throws `UsageLimitExceededError`.

  **`verify` inline-PEM parsing.** `vaultkeeper verify --public-key`/`--signature` now reject inline PEM material with a clear, actionable usage error (exit 2) instead of node's opaque "argument is ambiguous" — the flags are file-path-only, and the message says so and points at the `--public-key=<path>` escape for a path that legitimately begins with a dash.

  **Unknown-command suggestion.** An unrecognized subcommand now prints an npm/git/cargo-style `Did you mean '<closest>'?` suggestion (e.g. `doctro` → `doctor`) plus a one-line pointer to `vaultkeeper --help` and the docs, giving tarball-only users a discovery path.

  **README Quick Start.** The CLI Quick Start code block now includes an inline `--config-dir`/`VAULTKEEPER_CONFIG_DIR` reminder so a copy-paster gets the isolated-config guidance that was previously only in prose.

- [#79](https://github.com/mike-north/vaultkeeper/pull/79) [`bfa32f3`](https://github.com/mike-north/vaultkeeper/commit/bfa32f36f18963b67a318ff21a56fac2216dcedd) Thanks [@mike-north](https://github.com/mike-north)! - Make the CLI's trust-on-first-use (TOFU) model functional. `vaultkeeper approve --script <path>` now computes the script's SHA-256 and records it in the trust manifest (idempotently), and `vaultkeeper exec` consults the manifest before prompting: a caller whose current hash is already approved runs without an interactive prompt and reports a verified trust state, while a modified or unapproved caller is treated as untrusted. The library gains two public methods on `VaultKeeper` — `approveExecutable()` and `checkExecutableTrust()` — plus the `ExecutableTrustStatus` type, which back this behavior.

- [#196](https://github.com/mike-north/vaultkeeper/pull/196) [`7ee1a61`](https://github.com/mike-north/vaultkeeper/commit/7ee1a61b15a044db2444970adc2c3d7013f5fa47) Thanks [@mike-north](https://github.com/mike-north)! - Type-enforce the `setup()` trust choice, fix the quick-start rebuild footgun, and polish docs and CLI usage errors.

  **`SetupOptions` is now a discriminated union (type-enforced trust XOR).** `VaultKeeper.setup()`'s options argument is required and must carry **exactly one** of `executablePath` (TOFU verification) or `skipTrust: true` (development opt-out). Supplying neither — including a bare `setup('NAME')` or `setup('NAME', {})` — or both is now a **compile-time** error rather than a runtime-only failure; `ExecutableTrustRequiredError` remains the runtime backstop for untyped (plain-JavaScript) callers. `SetupOptionsBase` is exported for the common (non-trust) options. `@vaultkeeper/test-helpers` gains a matching public `TestVaultSetupOptions` type; `TestVault.setup()` keeps its permissive, trust-choice-optional signature (it still defaults to `skipTrust: true`).

  **Quick-start rebuild footgun fixed.** The library quick start no longer steers first-timers to `executablePath: process.argv[1]`, which pins TOFU trust to the compiled entry-file hash and throws `IdentityMismatchError` on the next run after any rebuild. The runnable snippets now use the development-safe `{ skipTrust: true }`, with an inline warning and a clearly-framed production example that binds a **stable** anchor (a released binary or `process.execPath`), plus a cross-reference to Development mode for frequently-rebuilt local callers.

  **Docs and CLI papercuts.** Documented `exec()`'s `[REDACTED]`-by-default output redaction and the `redact: false` opt-out in the library README; clarified that `VaultKeeper.init()` is in-memory and does not write `config.json` (only the CLI `config init` does); clarified that pre-approving a caller is a required first step for non-interactive/CI first `exec` (CLI) versus auto-recorded on first encounter (library); and documented the WASM `doctor()` unscoped required-vs-informational semantics. The CLI now prints a `Usage:` block (and exits 2) for an unknown top-level flag, matching the unknown-command and subcommand-level usage errors.

- Updated dependencies [[`46df0b0`](https://github.com/mike-north/vaultkeeper/commit/46df0b081432a3b14570a2599e27861f7ecc85bc), [`f863dfc`](https://github.com/mike-north/vaultkeeper/commit/f863dfcbf49cfdb9700cd3438388a2218155d5f1), [`75685ac`](https://github.com/mike-north/vaultkeeper/commit/75685ac1369870f901a7fdcecd815130d42355be), [`90a4127`](https://github.com/mike-north/vaultkeeper/commit/90a412791bdd3436c0c8c0e61179a5df1da664d5), [`4ebfa5d`](https://github.com/mike-north/vaultkeeper/commit/4ebfa5d2884da2984fde6736fa6f63dcb6524f06), [`94db84c`](https://github.com/mike-north/vaultkeeper/commit/94db84c9b99d6221c8e0ae1121d9d48bf1e62d4d), [`f24de45`](https://github.com/mike-north/vaultkeeper/commit/f24de45dc1f67ec513b8155b86b11102b14fb31f), [`eec6581`](https://github.com/mike-north/vaultkeeper/commit/eec658100b7728d76a918a2fa59b870e74315560), [`7f9da7a`](https://github.com/mike-north/vaultkeeper/commit/7f9da7a65c3f50bada97d7e0bb6a21770f9a9d2c), [`0ca9d3f`](https://github.com/mike-north/vaultkeeper/commit/0ca9d3fa5ab7a4bca5a92a8c62904ea279e8bfb3), [`b270562`](https://github.com/mike-north/vaultkeeper/commit/b27056208dead4ec5c1fd10007d64649bec2e02c), [`5c47f18`](https://github.com/mike-north/vaultkeeper/commit/5c47f180ead28ba855a7ab367dc69313a6885ba6), [`cfcd61b`](https://github.com/mike-north/vaultkeeper/commit/cfcd61bce6da0e180000f15d9676218b58fc60dd), [`a822564`](https://github.com/mike-north/vaultkeeper/commit/a8225649de1d9ab062055ef3eab96374cc31e2f9), [`f5edcd9`](https://github.com/mike-north/vaultkeeper/commit/f5edcd9ed0ca51b2f86b61db7701fa3ced46e031), [`88684f1`](https://github.com/mike-north/vaultkeeper/commit/88684f14bc2128dd907302e4e2e84fc36ee1f78c), [`7c8ab85`](https://github.com/mike-north/vaultkeeper/commit/7c8ab857859049fce5d9e1518d13a2b126293540), [`16f67a9`](https://github.com/mike-north/vaultkeeper/commit/16f67a90c223b1fdab9785f777964d12f71b2b37), [`2705b3a`](https://github.com/mike-north/vaultkeeper/commit/2705b3ad33ed0c2036d54b1eabbb066ebf3355c1), [`d511437`](https://github.com/mike-north/vaultkeeper/commit/d511437d2b8035a3f530033b80a488281c3e495d), [`2d848a7`](https://github.com/mike-north/vaultkeeper/commit/2d848a7bdccf5a04c2a99a96fd39d050cbf0c13f), [`c7f0068`](https://github.com/mike-north/vaultkeeper/commit/c7f0068145e4b8f7526a3436864ea26e337112fb), [`9f06652`](https://github.com/mike-north/vaultkeeper/commit/9f066521adfd21042e59e7b27ea4457dec446b2b), [`16e68b0`](https://github.com/mike-north/vaultkeeper/commit/16e68b0eccae39fc1b98fc501061da176a681e6e), [`c521414`](https://github.com/mike-north/vaultkeeper/commit/c521414caf844cf7d740e25faf271bcb320360f5), [`414bb05`](https://github.com/mike-north/vaultkeeper/commit/414bb0512743b454359d12750fb69d969cb9b4c3), [`ea628e5`](https://github.com/mike-north/vaultkeeper/commit/ea628e59d23d727a5e89807cf179549547604fbd), [`7f46237`](https://github.com/mike-north/vaultkeeper/commit/7f46237a7c5a0fd599db978604043f068ed5500b), [`f6e692b`](https://github.com/mike-north/vaultkeeper/commit/f6e692b9e3b4de263359f0da252bc00dc9b7767c), [`8fd800c`](https://github.com/mike-north/vaultkeeper/commit/8fd800cb77a9afaabcec01dce530e3d381120f93), [`26c876c`](https://github.com/mike-north/vaultkeeper/commit/26c876c4ba58eff1639cf6e2307f8c01fe5d85bd), [`ebfcd1d`](https://github.com/mike-north/vaultkeeper/commit/ebfcd1ddfa33c62e671f185d5ebcd4461bb1c80d), [`8124067`](https://github.com/mike-north/vaultkeeper/commit/81240672a37af315814c4bfda736ae7e339d8259), [`ce43052`](https://github.com/mike-north/vaultkeeper/commit/ce43052c9843eb4965e20a8fdad969b8de1858b2), [`38fafb5`](https://github.com/mike-north/vaultkeeper/commit/38fafb5bc661d360c96d2b79462a556a0dcd73ba), [`f20ea5a`](https://github.com/mike-north/vaultkeeper/commit/f20ea5a1aeded6fbdeaf0a937623737f5bc9c756), [`0c1daef`](https://github.com/mike-north/vaultkeeper/commit/0c1daef0466f23cf015d53f201f291029919951e), [`f2fe1d2`](https://github.com/mike-north/vaultkeeper/commit/f2fe1d2c4c3ade6e00680de65c4872aacfcc9793), [`5958996`](https://github.com/mike-north/vaultkeeper/commit/5958996c86094ce49116154924bf97ed05f14328), [`e800683`](https://github.com/mike-north/vaultkeeper/commit/e80068344a5ab0483b1cd98e55619c8b8f51b363), [`1c115c8`](https://github.com/mike-north/vaultkeeper/commit/1c115c8bc6f9bc80f02859f88a414e0452e5daeb), [`68d8b9c`](https://github.com/mike-north/vaultkeeper/commit/68d8b9cbc95b31086e4e4a94f6cf73ef279fff4d), [`11fe95d`](https://github.com/mike-north/vaultkeeper/commit/11fe95d6eb6836fdf7487274c4adc3c1bb539be3), [`bfa32f3`](https://github.com/mike-north/vaultkeeper/commit/bfa32f36f18963b67a318ff21a56fac2216dcedd), [`7ee1a61`](https://github.com/mike-north/vaultkeeper/commit/7ee1a61b15a044db2444970adc2c3d7013f5fa47), [`6b6d11a`](https://github.com/mike-north/vaultkeeper/commit/6b6d11a8187c066adf7f4d1fd8672cf77fa6819d), [`8ded257`](https://github.com/mike-north/vaultkeeper/commit/8ded257614332f9faf758b0a7c5e5c711528d8e3), [`a4a6cb7`](https://github.com/mike-north/vaultkeeper/commit/a4a6cb7809591237eb46027518681ffe5943f174), [`f2baa86`](https://github.com/mike-north/vaultkeeper/commit/f2baa86b9f329a5a557f27c5985a3950c351e7b5)]:
  - vaultkeeper@0.7.0

## 0.1.9

### Patch Changes

- Updated dependencies [[`5bbff5a`](https://github.com/mike-north/vaultkeeper/commit/5bbff5a7c6129a5240b3307c6915e4957b3889c1), [`5bbff5a`](https://github.com/mike-north/vaultkeeper/commit/5bbff5a7c6129a5240b3307c6915e4957b3889c1), [`a7540d1`](https://github.com/mike-north/vaultkeeper/commit/a7540d1b2198dceace73c1e1abba2dcd0f565f03), [`a7540d1`](https://github.com/mike-north/vaultkeeper/commit/a7540d1b2198dceace73c1e1abba2dcd0f565f03)]:
  - vaultkeeper@0.6.0

## 0.1.8

### Patch Changes

- Updated dependencies [[`a037cd6`](https://github.com/mike-north/vaultkeeper/commit/a037cd6e540ede350bc8a681a5ebbea8296a3793)]:
  - vaultkeeper@0.5.3

## 0.1.7

### Patch Changes

- Updated dependencies [[`f0fe162`](https://github.com/mike-north/vaultkeeper/commit/f0fe16247ebcfc33ad0dd65a57695a101ca07b61), [`3b5868f`](https://github.com/mike-north/vaultkeeper/commit/3b5868f676e6b4131e5d99c244246c7cbb325845)]:
  - vaultkeeper@0.5.2

## 0.1.6

### Patch Changes

- [#41](https://github.com/mike-north/vaultkeeper/pull/41) [`31262e9`](https://github.com/mike-north/vaultkeeper/commit/31262e9cc052a3ca6b5c6a81d143f8090794997d) Thanks [@mike-north](https://github.com/mike-north)! - Add `--skip-doctor` flag and `VAULTKEEPER_SKIP_DOCTOR=1` environment variable to CLI commands that initialize VaultKeeper. When set, preflight dependency checks are skipped — useful on systems where the native credential store is unavailable but the `file` backend is configured.

- [#40](https://github.com/mike-north/vaultkeeper/pull/40) [`dd82303`](https://github.com/mike-north/vaultkeeper/commit/dd823038b4b227a7fd6e3bb5e2a2675718f96353) Thanks [@mike-north](https://github.com/mike-north)! - Fix `config init` to generate platform-appropriate defaults: `keychain` on macOS, `dpapi` on Windows, `file` on Linux. Previously always defaulted to `keychain` which is macOS-only.

- Updated dependencies [[`003e497`](https://github.com/mike-north/vaultkeeper/commit/003e4972c6bf1c4b39e838ed32346a84e4396bee)]:
  - vaultkeeper@0.5.1

## 0.1.5

### Patch Changes

- [#35](https://github.com/mike-north/vaultkeeper/pull/35) [`5a907e1`](https://github.com/mike-north/vaultkeeper/commit/5a907e138ba336dc7da140170950c93b1c7f43ee) Thanks [@mike-north](https://github.com/mike-north)! - Patch release to verify end-to-end publishing pipeline after release infrastructure fixes (crates.io gating, workspace dependency version sync, cross-platform compatibility)

## 0.1.4

### Patch Changes

- [#20](https://github.com/mike-north/vaultkeeper/pull/20) [`c65c107`](https://github.com/mike-north/vaultkeeper/commit/c65c1076802dcc5e2710c47fd60e3f1771858fe1) Thanks [@mike-north](https://github.com/mike-north)! - Add VAULTKEEPER_CONFIG_DIR env var for test isolation and introduce @vaultkeeper/cli-test-helpers package with reusable CLI test infrastructure

- Updated dependencies [[`c65c107`](https://github.com/mike-north/vaultkeeper/commit/c65c1076802dcc5e2710c47fd60e3f1771858fe1), [`3f95e3b`](https://github.com/mike-north/vaultkeeper/commit/3f95e3b954cb6f046e34f2155da9ff945d47c16e)]:
  - vaultkeeper@1.0.1

## 0.1.3

### Patch Changes

- Updated dependencies [[`5353518`](https://github.com/mike-north/vaultkeeper/commit/535351866ef9cb4e77edb9b2b757911e74b3b402), [`c0d36c5`](https://github.com/mike-north/vaultkeeper/commit/c0d36c5f5bdc7848574863514bfe53e23ce83d42)]:
  - vaultkeeper@1.0.0

## 0.1.2

### Patch Changes

- Updated dependencies [[`a1d2e57`](https://github.com/mike-north/vaultkeeper/commit/a1d2e57fe3b2132d63755c31acc332b90ae7a799)]:
  - vaultkeeper@0.4.0

## 0.1.1

### Patch Changes

- Updated dependencies [[`a000092`](https://github.com/mike-north/vaultkeeper/commit/a000092848e94e130893d145d07a8b8bf6fc1ead), [`c2c4e8c`](https://github.com/mike-north/vaultkeeper/commit/c2c4e8cfd94e624b4ad7dfd2f3b22a6046d91c8e), [`7398ff6`](https://github.com/mike-north/vaultkeeper/commit/7398ff6352b8d3e39e562ace50b8caa8ef998882)]:
  - vaultkeeper@0.3.0

## 0.1.0

### Minor Changes

- [#8](https://github.com/mike-north/vaultkeeper/pull/8) [`e9fc9bb`](https://github.com/mike-north/vaultkeeper/commit/e9fc9bb060cd6b6cf510fb0e6b1a9076eab00088) Thanks [@mike-north](https://github.com/mike-north)! - Add `@vaultkeeper/cli` package — command-line interface for vaultkeeper secret management. Provides `vaultkeeper exec` for injecting secrets as environment variables with output redaction, plus commands for doctor checks, secret storage, key rotation, and configuration management.

### Patch Changes

- Updated dependencies [[`1f1412c`](https://github.com/mike-north/vaultkeeper/commit/1f1412c7b76c7810b395df4b9de44ebe21a16188)]:
  - vaultkeeper@0.2.0
