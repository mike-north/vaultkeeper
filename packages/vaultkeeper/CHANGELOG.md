# vaultkeeper

## 0.7.0

### Minor Changes

- [#89](https://github.com/mike-north/vaultkeeper/pull/89) [`46df0b0`](https://github.com/mike-north/vaultkeeper/commit/46df0b081432a3b14570a2599e27861f7ecc85bc) Thanks [@mike-north](https://github.com/mike-north)! - Make backend selection visible and overridable from the CLI and introspectable from the library.
  - `vaultkeeper config init --backend <type>` now writes a config whose first enabled backend is `<type>`. Valid values are the registered backend types; an unknown value exits 2 and lists the valid types.
  - Any unknown flag on a `config` subcommand (`config init`, `config show`) now exits 2 with an "unknown option" error instead of being silently ignored — a typo can no longer send secrets to an unintended credential store.
  - `config init` output now states which backend was configured and how to change it. `config show` reports the resolved active backend (first enabled).
  - New public `platformNativeBackendType()` reports the OS-native credential store for the current platform (`keychain` on macOS, `dpapi` on Windows, `secret-tool` on Linux, `file` on other platforms) — the store you can opt into with `--backend`.
  - New public `VaultKeeper.activeBackendType` getter exposes the type of the active (first enabled) backend at runtime.

- [#92](https://github.com/mike-north/vaultkeeper/pull/92) [`75685ac`](https://github.com/mike-north/vaultkeeper/commit/75685ac1369870f901a7fdcecd815130d42355be) Thanks [@mike-north](https://github.com/mike-north)! - Add a global `--config-dir <path>` flag / `VAULTKEEPER_CONFIG_DIR` environment variable to the CLI so every command (`store`, `delete`, `exec`, `approve`, `dev-mode`, `doctor`, `config`, `rotate-key`, `revoke-key`) can be pointed at an isolated config directory — the flag wins over the env var, which wins over the platform default. `config init` creates the override directory as needed, and `config show` reports the path it loaded from. The library's `getDefaultConfigDir()` and `loadConfig()` are now public so embedders and the CLI share the same resolution logic. `@vaultkeeper/cli-test-helpers`'s `createCliTestEnv()` gains a `configDirMode` option (`'env'` | `'flag'`) and no longer manipulates the subprocess's `HOME` directory to achieve isolation.

- [#160](https://github.com/mike-north/vaultkeeper/pull/160) [`90a4127`](https://github.com/mike-north/vaultkeeper/commit/90a412791bdd3436c0c8c0e61179a5df1da664d5) Thanks [@mike-north](https://github.com/mike-north)! - Fixed CLI error output so recovery hints repair the file they diagnose and read cleanly.
  - The invalid-config recovery hint now carries an explicit `--config-dir '<dir>'` whenever a non-default config directory is active (from `--config-dir` or `VAULTKEEPER_CONFIG_DIR`), so the copy-pasted `vaultkeeper config init --force …` command repairs the exact diagnosed file instead of writing a fresh config to the platform default and leaving the corrupt file untouched. The default-directory case stays bare (no path is leaked). A new `getPlatformDefaultConfigDir()` export computes the machine default independent of `VAULTKEEPER_CONFIG_DIR`, so a directory that came only from the environment variable still gets an explicit flag (a fresh shell running the pasted command won't have that variable set); `getDefaultConfigDir()` now delegates to it.
  - `FilesystemError` now renders a human message from its typed `path`/`permission` fields — plainly stating whether the file is missing or permission-denied, with a suggested next step — instead of leaking the raw Node `ENOENT: … open '<path>'` text. The typed class and its fields are unchanged.
  - `doctor` prints the config remediation exactly once (under "Next steps") instead of duplicating it inline on the failing config check.

- [#95](https://github.com/mike-north/vaultkeeper/pull/95) [`4ebfa5d`](https://github.com/mike-north/vaultkeeper/commit/4ebfa5d2884da2984fde6736fa6f63dcb6524f06) Thanks [@mike-north](https://github.com/mike-north)! - Uniform CLI exit-code taxonomy (0 success / 1 runtime failure / 2 usage error) applied everywhere: a top-level typo like `vaultkeeper --bogus` now exits 2 with an error instead of silently exiting 0, and an unrecognized flag on `store`, `delete`, `exec`, `approve`, `dev-mode`, or `doctor` now exits 2 instead of a bare fatal error (exit 1).

  `store` (and `delete`, for consistency) now reject an empty or whitespace-only `--name` with exit 2 and the same error style as a missing flag, instead of persisting a near-unreachable secret or surfacing a generic runtime error. Allowed `--name` characters (letters, digits, `.`, `_`, `-`, `/`) are documented in `--help`.

  `exec` now validates that the secret exists before the caller-approval/TTY gate, so `exec --secret <nonexistent> ...` reports a clear `SecretNotFoundError` regardless of TTY, instead of being masked by the generic "requires interactive approval" message. This is backed by a new public `VaultKeeper.secretExists(name)` method — a side-effect-free existence check that never touches the TOFU trust manifest.

  `config init --help` and `config show --help` now print help for that subcommand instead of the parent `config` help. `exec --help` includes a worked `--caller` example.

- [#94](https://github.com/mike-north/vaultkeeper/pull/94) [`0ca9d3f`](https://github.com/mike-north/vaultkeeper/commit/0ca9d3fa5ab7a4bca5a92a8c62904ea279e8bfb3) Thanks [@mike-north](https://github.com/mike-north)! - `doctor` and `config show` now detect an invalid config file instead of silently ignoring it. `doctor` validates the config file (when present) as part of its preflight checks and reports a failing `config` check with the parse/validation error and file path, exiting non-zero. `config show` on invalid JSON now exits non-zero with the parse error (including a line/column location when available) instead of dumping the raw file with exit 0. Every config parse/validation error raised by `loadConfig()` — surfaced through `store`, `delete`, `exec`, `config show`, and `doctor` alike — now includes the config file path, the parse location where available, and a remediation hint naming `vaultkeeper config init`.

  `loadConfig()` now falls back to platform defaults only when the config file is missing (`ENOENT`). A present-but-unreadable file (e.g. a permissions error) is rethrown as a typed `FilesystemError` instead of being silently treated as "no config" — a genuinely broken config was previously invisible to `doctor` and `config show`.

  The "no config file" story is now uniform across `store`, `delete`, `exec`, `config show`, and `doctor`: each falls back to platform defaults and prints a one-line notice naming the resolved backend and `vaultkeeper config init` (e.g. `No config file found; using platform defaults (keychain). Run 'vaultkeeper config init' to persist one.`). Previously `config show` errored with exit 1 on a missing config file while the other commands defaulted silently; `config show` now defaults and reports it like the rest.

  New public `ConfigParseError` (with `path` and `location` fields) is thrown on invalid config JSON. `ConfigValidationError` gains an optional `configFilePath` field. `PreflightCheckStatus` gains an `'invalid'` value, and `RunDoctorOptions` gains an optional `configDir` field that lets `runDoctor`/`VaultKeeper.doctor()` load and validate the config itself.

- [#120](https://github.com/mike-north/vaultkeeper/pull/120) [`b270562`](https://github.com/mike-north/vaultkeeper/commit/b27056208dead4ec5c1fd10007d64649bec2e02c) Thanks [@mike-north](https://github.com/mike-north)! - Make `@1password/sdk` an optional peer dependency instead of a runtime dependency. Installing `vaultkeeper` no longer pulls `@1password/sdk` (and its `@1password/sdk-core` transitive) into the dependency closure — the file-backend path stays `jose`-only. The 1Password backend now loads the SDK lazily (via dynamic `import()`) only when that backend is actually used, and fails with a typed `PluginNotFoundError` naming the missing `@1password/sdk` peer when it is not installed. To use the 1Password backend, install `@1password/sdk` alongside `vaultkeeper`.

- [#126](https://github.com/mike-north/vaultkeeper/pull/126) [`cfcd61b`](https://github.com/mike-north/vaultkeeper/commit/cfcd61bce6da0e180000f15d9676218b58fc60dd) Thanks [@mike-north](https://github.com/mike-north)! - Fix `dev-mode` invalid-action misdiagnosis and audit `config.ts`/the file backend for plain `Error` throws.
  - `vaultkeeper dev-mode <action> --script <path>` now distinguishes an invalid action from missing args: an unrecognized action (e.g. `banana`) emits `unknown action "<x>" (expected "enable" or "disable")` (exit 2), while `missing action or --script flag` is reserved for genuinely absent arguments.
  - The encrypted-file secret backend (`FileBackend`) now surfaces `EACCES`/permission failures reading, writing, or deleting a secret entry as a typed `FilesystemError` instead of the raw Node.js error.
  - Added a new `DecryptionError` (extends `VaultError`) for when a stored secret entry fails to decrypt (corrupted ciphertext or a failed AES-GCM auth tag check) — previously thrown as a plain `Error`.

- [#145](https://github.com/mike-north/vaultkeeper/pull/145) [`f5edcd9`](https://github.com/mike-north/vaultkeeper/commit/f5edcd9ed0ca51b2f86b61db7701fa3ced46e031) Thanks [@mike-north](https://github.com/mike-north)! - Give the doctor `config` preflight check structured error context so the CLI can render a CLI-native remediation instead of the library's install text.
  - The public `PreflightCheck` shape gains an optional `error` field (`PreflightCheckError`: `kind` + `configPath` + optional parse `location`) carrying remediation-free, machine-readable context when the `config` check fails on a present-but-invalid config file. A consumer can build its own audience-appropriate remediation from these fields instead of parsing the human-readable `reason` prose.
  - `vaultkeeper doctor` run against a corrupt or invalid config now shows the CLI-native remediation (config path + `vaultkeeper config init --force`), wording-consistent with every other command, and no longer tells a user already running the CLI to "install @vaultkeeper/cli". The library's own `reason` text is unchanged for library consumers.

- [#121](https://github.com/mike-north/vaultkeeper/pull/121) [`7c8ab85`](https://github.com/mike-north/vaultkeeper/commit/7c8ab857859049fce5d9e1518d13a2b126293540) Thanks [@mike-north](https://github.com/mike-north)! - Scope `doctor` to the active/configured backend so a fresh install no longer looks broken. Previously `doctor` rendered every non-`'ok'` check with a failing `✗` icon, including plugin-backend tools (`ykman`, `op`) that weren't configured — on the post-#98 `file`-default install, this meant the very first `doctor` run showed a failing check for a YubiKey/1Password tool the user never opted into.

  `PreflightResult.checks` entries are now `ScopedPreflightCheck` (a `PreflightCheck` plus `required: boolean`), reflecting whether each dependency is required for the active/configured backend(s). The CLI only renders the `✗` icon for checks that are both required and failing; unmet optional checks still surface, without the failure icon, in the `Warnings` section. Opt-in backends still get their dependency checks promoted to required when configured (e.g. `--backend yubikey` requires `ykman`).

- [#177](https://github.com/mike-north/vaultkeeper/pull/177) [`16f67a9`](https://github.com/mike-north/vaultkeeper/commit/16f67a90c223b1fdab9785f777964d12f71b2b37) Thanks [@mike-north](https://github.com/mike-north)! - Render an unreadable config directory as a failing doctor check instead of a raw crash.
  - `vaultkeeper doctor` run against a config directory the process cannot read (e.g. a `chmod 000` directory, so reading `config.json` inside it fails with `EACCES`/`EPERM`) previously aborted with a raw Node `Error: EACCES: permission denied, access '.../config.json'` — no typed class, no fix hint, and no checks rendered at all. It now surfaces the read failure as a failing `config` check (just like a parse or validation failure), keeps rendering the other checks, prints a permissions-oriented remediation under "Next steps", and exits non-zero. The raw errno string no longer leaks to the user.
  - The public `PreflightCheckErrorKind` gains a `'config-read'` member, and `PreflightCheckError` gains an optional `code` field carrying the underlying errno (e.g. `EACCES`), so a consumer can build a permissions-specific remediation. `config init --force` is deliberately not suggested for this failure — it cannot repair a config the process cannot read.

- [#195](https://github.com/mike-north/vaultkeeper/pull/195) [`c7f0068`](https://github.com/mike-north/vaultkeeper/commit/c7f0068145e4b8f7526a3436864ea26e337112fb) Thanks [@mike-north](https://github.com/mike-north)! - Redact injected secrets from library `exec()` output, and give the CLI a typed error when a wrapped command cannot be spawned.
  - `VaultKeeper.exec()` now redacts every injected secret value from the captured `stdout`/`stderr` before returning, replacing each occurrence with `[REDACTED]`. This upholds the documented guarantee that the raw secret never appears in the return value, even when the spawned command echoes it. Multi-secret (`{{secret:name}}`) injections redact all injected values. Pass the new `ExecRequest.redact: false` to opt out and receive raw output. The redaction logic is shared with the CLI's streaming `--no-redact` path via the new public `redactSecrets` helper, so the two surfaces cannot drift.
  - The CLI `exec` command now maps a spawn failure of the wrapped command (`ENOENT` for a nonexistent command, `EACCES` for a non-executable file) to a typed `ExecError` with remediation, rendered through the CLI's typed-error formatter, instead of leaking a bare `Error: spawn <path> ENOENT`.

- [#141](https://github.com/mike-north/vaultkeeper/pull/141) [`16e68b0`](https://github.com/mike-north/vaultkeeper/commit/16e68b0eccae39fc1b98fc501061da176a681e6e) Thanks [@mike-north](https://github.com/mike-north)! - `FilesystemError` now preserves the underlying Node.js filesystem failure it wraps. A new `readonly code: string | undefined` property exposes the original errno code (e.g. `EACCES`, `ENOSPC`, `EISDIR`) so callers can discriminate the failure kind without parsing the message text, and the original error is now recorded as the standard `Error.cause`. The two near-duplicate internal helpers that built `FilesystemError` (one in the file backend, one in the shared at-rest key-wrapping module) have been merged into a single shared helper so this population happens in one place.

- [#174](https://github.com/mike-north/vaultkeeper/pull/174) [`ea628e5`](https://github.com/mike-north/vaultkeeper/commit/ea628e59d23d727a5e89807cf179549547604fbd) Thanks [@mike-north](https://github.com/mike-north)! - Fix two library rough edges surfaced by the direct-integration path.
  - `VaultKeeper.activeBackendType` no longer throws `BackendUnavailableError` when a backend was injected via `init({ backend })`. It now reports the injected backend's declared `type` (or the stable `'custom'` sentinel if it declares an empty type). `setup()` derives the token's `bkd` claim from the same rule, so an injected backend with an empty type mints a valid token (`bkd: "custom"`) instead of one rejected by claim validation. The config-driven path is unchanged.
  - `SecretAccessor.read()` now passes the callback's return value through: `read<T>(cb: (buf: Buffer) => T): T`, so `const value = accessor.read((buf) => buf.toString('utf8'))` yields the derived value instead of `undefined`. The buffer is still zeroed after the callback returns, so returning the raw buffer only ever yields zeroed bytes — derive a value inside the callback.

- [#222](https://github.com/mike-north/vaultkeeper/pull/222) [`8fd800c`](https://github.com/mike-north/vaultkeeper/commit/8fd800cb77a9afaabcec01dce530e3d381120f93) Thanks [@mike-north](https://github.com/mike-north)! - Extend the 1Password per-access worker with a `store`/`delete` write path so `--require-presence-per-use` covers writes, not just reads. Previously the per-access worker was read-only, so `OnePasswordBackend` reported `presenceEnforcedOperations: ['read']` and a flagged `store`/`delete` failed closed with `NotCapableError` — correct, but limited. Now every keyed operation (`retrieve`, `store`, `delete`) spawns its own fresh worker process forcing a distinct biometric approval, `presenceEnforcedOperations` reports `['read', 'store', 'delete']`, and the earlier `NotCapableError` refusal is replaced by the same fresh-action guarantee reads already had. The secret value for `store` is delivered to the worker over stdin — never argv — so it never appears in a process listing, shell history, or log. A declined presence action throws `PresenceDeclinedError`; a timed-out one throws `PresenceTimeoutError`.

- [#93](https://github.com/mike-north/vaultkeeper/pull/93) [`8124067`](https://github.com/mike-north/vaultkeeper/commit/81240672a37af315814c4bfda736ae7e339d8259) Thanks [@mike-north](https://github.com/mike-north)! - Persist key material across processes so cached tokens and the rotation grace period work between CLI invocations.
  - `KeyManager` encryption keys are now persisted under the config directory, encrypted at rest with AES-256-GCM under an owner-only (`0600`) wrapping key — reusing the same authenticated-cipher primitives as the file backend. Persistence is active only when `VaultKeeper` loads its configuration from disk (no injected `config`/`backend`); instances built with an injected `config` or `backend` keep keys in memory, so tests and embedders stay hermetic.
  - A JWE minted by one process is now authorizable by a later process within its validity window: its `kid` still resolves after the minting process exits. Previously every process generated fresh keys, so a cached token always failed with `KeyRevokedError`.
  - `vaultkeeper exec --cache` now genuinely reuses a cached token on a second run by the same trusted caller — without re-minting and without the misleading "Cached token expired" message. Cached tokens are reusable until they expire (the secret's TTL) or the key is rotated/revoked, after which `exec` transparently mints a fresh one.
  - The cached-token path no longer collapses every authorization failure into a generic "expired" message. Each failure now surfaces its actual cause (e.g. `KeyRevokedError`, `TokenExpiredError`).
  - The rotation grace-period guard now survives across processes: running `rotate-key` twice while the previous key is still in its grace period fails the second time with `RotationInProgressError` (non-zero exit) instead of silently rotating again.

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

- [#108](https://github.com/mike-north/vaultkeeper/pull/108) [`5958996`](https://github.com/mike-north/vaultkeeper/commit/5958996c86094ce49116154924bf97ed05f14328) Thanks [@mike-north](https://github.com/mike-north)! - Make the zero-config default backend safe: the shortest documented getting-started path can no longer silently write a secret to your real OS credential store.
  - With no config file present, a bare `VaultKeeper.init()` — and `vaultkeeper config init` with no `--backend` — now resolves to the portable, self-contained `file` backend on **every** platform, including macOS and Windows. Previously it targeted the OS-native credential store (macOS Keychain, Windows DPAPI), so copy-pasting the first documented example could store a secret in the real login keychain before the user knew backends existed.
  - The platform-native store stays fully supported as an explicit opt-in: `vaultkeeper config init --backend keychain` / `--backend dpapi`, or an explicit config.
  - New public `defaultBackendType()` returns the zero-config default (`'file'`) on every platform. The former `platformDefaultBackendType()` is renamed to `platformNativeBackendType()` — it never was the zero-config default and now reads as what it is: the OS-native store you can opt into.
  - The `doctor` / `store` (and `delete` / `exec` / `config show`) "no config file" advisory now names the `file` default and spells out the remediation as `vaultkeeper config init --backend file`, never a bare `config init`, so following the hint verbatim persists exactly the backend that was in effect.

  Note: this changes only the TypeScript library and Node.js CLI. The native Rust CLI's zero-config default is unchanged for now.

- [#76](https://github.com/mike-north/vaultkeeper/pull/76) [`1c115c8`](https://github.com/mike-north/vaultkeeper/commit/1c115c8bc6f9bc80f02859f88a414e0452e5daeb) Thanks [@mike-north](https://github.com/mike-north)! - sign() now throws a typed InvalidKeyMaterialError (instead of a raw OpenSSL decoder error) when the stored secret is not valid PEM/DER private key material; delegatedFetch() now wraps network failures in a typed FetchError instead of letting the raw fetch() rejection escape

- [#159](https://github.com/mike-north/vaultkeeper/pull/159) [`68d8b9c`](https://github.com/mike-north/vaultkeeper/commit/68d8b9cbc95b31086e4e4a94f6cf73ef279fff4d) Thanks [@mike-north](https://github.com/mike-north)! - Make signing and verification of arbitrary challenges a first-class, CLI-exposed primitive with a stable, third-party-verifiable signature format.
  - New CLI commands (`@vaultkeeper/cli`): `key create --name <n> --type ed25519` provisions a signing keypair (unknown `--type` exits 2, never a silent default); `key export --name <n>` prints the SPKI PEM public key; `sign --name <n>` reads all of stdin and writes exactly the detached signature to stdout (pipeline-safe; status on stderr); `verify --public-key <pem> --signature <sig>` verifies a detached signature fully offline (no config, backend, or key store). `verify` adds exit code `3` for a signature that did not verify — a deliberate, documented exception to the `0/1/2` taxonomy so scripts can tell a bad signature from a broken tool.
  - Signatures are detached-payload Compact JWS (RFC 7515 §7.2.2 + RFC 7797 `b64:false`, `crit:["b64"]`, `alg` EdDSA/Ed25519). Any standards-compliant JOSE library can verify a signature given the payload and the public key.
  - Signing keys are a distinct resource from secrets: a new backend signing contract (`generateSigningKey`/`getPublicKey`/`signWithKey`, mirroring `ListableBackend`) keeps private key material backend-side. It never flows through `store()`/`retrieve()`/`fetch()`/`exec()` or a capability token's claims, and `fetch()`/`exec()`/`getSecret()` reject a signing-key token outright. The `file` backend implements the contract; backends that do not fail with a typed `SigningNotSupportedError`.
  - Breaking (library): the `SignRequest`/`SignResult`/`VerifyRequest` shapes and `VaultKeeper.sign()`/`VaultKeeper.verify()` are reshaped to the JWS contract. `sign()` now takes a signing-key capability token from the new `authorizeSigningKey()` and returns `{ jws }`; `verify()` is async and takes `{ payload, jws, publicKey }`. New public API: `createSigningKey()`, `exportPublicKey()`, `authorizeSigningKey()`, `SigningBackend`/`isSigningBackend`, `SigningAlgorithm`, `SigningPublicKey`, and the `SigningKeyNotFoundError`/`SigningNotSupportedError` typed errors.

- [#91](https://github.com/mike-north/vaultkeeper/pull/91) [`11fe95d`](https://github.com/mike-north/vaultkeeper/commit/11fe95d6eb6836fdf7487274c4adc3c1bb539be3) Thanks [@mike-north](https://github.com/mike-north)! - Add a `backend` option to `VaultKeeperOptions` that accepts a `SecretBackend` instance directly, so tests and embedders can inject a backend without registering it globally via `BackendRegistry` or hand-assembling a full `VaultConfig`. When `backend` is set it always takes precedence over the backend that `config.backends` (or the config loaded from `configDir`) would otherwise resolve; other config fields still come from `config`/`configDir` when supplied, and a minimal built-in default config is used automatically when `config` is omitted. The README's "Testing your own code" and "Injecting a backend directly" sections document a dependency-injection pattern for testing code that uses `VaultKeeper`.

- [#79](https://github.com/mike-north/vaultkeeper/pull/79) [`bfa32f3`](https://github.com/mike-north/vaultkeeper/commit/bfa32f36f18963b67a318ff21a56fac2216dcedd) Thanks [@mike-north](https://github.com/mike-north)! - Make the CLI's trust-on-first-use (TOFU) model functional. `vaultkeeper approve --script <path>` now computes the script's SHA-256 and records it in the trust manifest (idempotently), and `vaultkeeper exec` consults the manifest before prompting: a caller whose current hash is already approved runs without an interactive prompt and reports a verified trust state, while a modified or unapproved caller is treated as untrusted. The library gains two public methods on `VaultKeeper` — `approveExecutable()` and `checkExecutableTrust()` — plus the `ExecutableTrustStatus` type, which back this behavior.

- [#196](https://github.com/mike-north/vaultkeeper/pull/196) [`7ee1a61`](https://github.com/mike-north/vaultkeeper/commit/7ee1a61b15a044db2444970adc2c3d7013f5fa47) Thanks [@mike-north](https://github.com/mike-north)! - Type-enforce the `setup()` trust choice, fix the quick-start rebuild footgun, and polish docs and CLI usage errors.

  **`SetupOptions` is now a discriminated union (type-enforced trust XOR).** `VaultKeeper.setup()`'s options argument is required and must carry **exactly one** of `executablePath` (TOFU verification) or `skipTrust: true` (development opt-out). Supplying neither — including a bare `setup('NAME')` or `setup('NAME', {})` — or both is now a **compile-time** error rather than a runtime-only failure; `ExecutableTrustRequiredError` remains the runtime backstop for untyped (plain-JavaScript) callers. `SetupOptionsBase` is exported for the common (non-trust) options. `@vaultkeeper/test-helpers` gains a matching public `TestVaultSetupOptions` type; `TestVault.setup()` keeps its permissive, trust-choice-optional signature (it still defaults to `skipTrust: true`).

  **Quick-start rebuild footgun fixed.** The library quick start no longer steers first-timers to `executablePath: process.argv[1]`, which pins TOFU trust to the compiled entry-file hash and throws `IdentityMismatchError` on the next run after any rebuild. The runnable snippets now use the development-safe `{ skipTrust: true }`, with an inline warning and a clearly-framed production example that binds a **stable** anchor (a released binary or `process.execPath`), plus a cross-reference to Development mode for frequently-rebuilt local callers.

  **Docs and CLI papercuts.** Documented `exec()`'s `[REDACTED]`-by-default output redaction and the `redact: false` opt-out in the library README; clarified that `VaultKeeper.init()` is in-memory and does not write `config.json` (only the CLI `config init` does); clarified that pre-approving a caller is a required first step for non-interactive/CI first `exec` (CLI) versus auto-recorded on first encounter (library); and documented the WASM `doctor()` unscoped required-vs-informational semantics. The CLI now prints a `Usage:` block (and exits 2) for an unknown top-level flag, matching the unknown-command and subcommand-level usage errors.

### Patch Changes

- [#231](https://github.com/mike-north/vaultkeeper/pull/231) [`f863dfc`](https://github.com/mike-north/vaultkeeper/commit/f863dfcbf49cfdb9700cd3438388a2218155d5f1) Thanks [@mike-north](https://github.com/mike-north)! - Wrap config-directory CREATION failures in a typed `FilesystemError` instead of leaking a raw Node error.

  `vaultkeeper config init` (and the first `store`, which persists key state before writing any secret) against a config directory whose parent is read-only previously aborted with the raw, unwrapped `Error: EACCES: permission denied, mkdir '<path>'` — no error class, no plain-English description, no fix hint. Only the config-directory READ paths had been wrapped previously.

  The directory-creation path now surfaces a typed `FilesystemError` (with the path and the underlying errno code) rendered through the CLI's error formatter with directory-specific wording and a parent-directory fix hint (check that the parent directory is writable, or choose a writable location with `--config-dir`). The raw `EACCES`/`mkdir` errno text no longer reaches the user, and the command still exits non-zero. The key-state write path is likewise wrapped.

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

- [#226](https://github.com/mike-north/vaultkeeper/pull/226) [`eec6581`](https://github.com/mike-north/vaultkeeper/commit/eec658100b7728d76a918a2fa59b870e74315560) Thanks [@mike-north](https://github.com/mike-north)! - Fixed the CLI README's sign/verify walkthrough: `sign` and `verify` now both read the challenge via `printf '%s'`, so each sees byte-identical stdin — the previous here-string form appended a trailing newline, making the documented example fail verification with exit 3. Shipped READMEs' runnable examples are now exercised by a CI example-fence check so a documented command sequence that stops working fails the build.

- [#105](https://github.com/mike-north/vaultkeeper/pull/105) [`7f9da7a`](https://github.com/mike-north/vaultkeeper/commit/7f9da7a65c3f50bada97d7e0bb6a21770f9a9d2c) Thanks [@mike-north](https://github.com/mike-north)! - Add a supported recovery path for a corrupt or unreadable `config.json`.
  - `vaultkeeper config init --force` now overwrites an existing config file, including one that's present-but-unparseable. `config init` without `--force` keeps its current non-destructive refusal, and now points at `config init --force` in its refusal message. `--force` composes with `--backend` (e.g. `config init --force --backend file`).
  - `ConfigParseError` (and the other `loadConfig` errors sharing its remediation hint) now names `vaultkeeper config init --force` instead of `vaultkeeper config init` — the previous hint sent users to a command that provably failed in the exact state that produced the error.

- [#204](https://github.com/mike-north/vaultkeeper/pull/204) [`5c47f18`](https://github.com/mike-north/vaultkeeper/commit/5c47f180ead28ba855a7ab367dc69313a6885ba6) Thanks [@mike-north](https://github.com/mike-north)! - Fix `VaultKeeper.setup()` recording TOFU (trust-on-first-use) trust for an executable before confirming the secret actually exists.

  `#resolveExecutableIdentity` ran trust verification — which durably records a first-encounter or Sigstore hash in the trust manifest — before `backend.retrieve()`. A `setup()` call for a nonexistent secret therefore still left the caller's hash permanently approved, letting an attacker (or a typo'd script) pre-seed TOFU trust without ever completing a legitimate first encounter; a later, real first encounter would then silently match the pre-seeded hash instead of being verified as new.

  Trust verification is now split into a verify phase (computes the hash and classifies it against the manifest, staging but not writing any first-encounter/Sigstore update) and a commit phase that only runs after `setup()`'s secret retrieval and token minting succeed. Shape validation (missing/conflicting/legacy-`'dev'`-sentinel trust choices) still fails fast before any backend read, and a TOFU hash conflict still fails without ever recording the new hash — only the successful first-encounter write is deferred.

- [#187](https://github.com/mike-north/vaultkeeper/pull/187) [`a822564`](https://github.com/mike-north/vaultkeeper/commit/a8225649de1d9ab062055ef3eab96374cc31e2f9) Thanks [@mike-north](https://github.com/mike-north)! - Ship a per-package `LICENSE` and align docs for signing/verification and packaging.
  - Every published package now carries its own `LICENSE` file and lists `LICENSE` + `README.md` explicitly in its `files` array, so the packaging declaration matches what npm actually ships (previously only a root `LICENSE` existed, which `npm pack` does not include in per-package tarballs). A packaging test now asserts `LICENSE` is present in each tarball.
  - Documented `sign()`'s precondition that the stored secret must be **PEM private-key** material — secrets are stored as strings and `crypto.createPrivateKey()` treats a string as PEM, so raw binary DER must be converted to PEM before storing; a plain-string secret throws `InvalidKeyMaterialError`. Added a distinct example key and a runnable end-to-end `generateKeyPairSync` → store → sign → verify walkthrough, plus `InvalidKeyMaterialError` in the repository README's error table.
  - Scoped the delegated access patterns (`fetch()`/`exec()`/`getSecret()`/`sign()`/`verify()`) explicitly to the TypeScript library and clarified that `@vaultkeeper/wasm`'s `executablePath` is a non-enforcing claim label, unlike this library's TOFU-verified `executablePath`.
  - Added a `getSecret()` code sample, a top-of-README quick-links/TL;DR block, a note that doctor deliberately checks all supported backends' tooling, and a more precise TypeScript-version note that shows the exact known-good consumer `compilerOptions` the CI matrix verifies across TypeScript 5.0.4–7.0.2.

- [#206](https://github.com/mike-north/vaultkeeper/pull/206) [`88684f1`](https://github.com/mike-north/vaultkeeper/commit/88684f14bc2128dd907302e4e2e84fc36ee1f78c) Thanks [@mike-north](https://github.com/mike-north)! - Surface the offending field in `doctor`'s remediation for a schema-invalid config.

  For a config that parses as JSON but fails schema validation (e.g. `backends: []`), `doctor`'s Next-steps previously said only that the config was invalid, omitting the field-level reason it gives for JSON-parse errors (which name the line/column). The `PreflightCheckError` structured context now carries the offending `field` for a `config-validation` failure — the validation analogue of a parse failure's `location` — so `doctor` renders it (e.g. "is invalid (`backends`)"), matching the wording every other command already used. No `reason` prose is parsed to do this.

- [#221](https://github.com/mike-north/vaultkeeper/pull/221) [`2705b3a`](https://github.com/mike-north/vaultkeeper/commit/2705b3ad33ed0c2036d54b1eabbb066ebf3355c1) Thanks [@mike-north](https://github.com/mike-north)! - Validate `backends[].type` against the registered backends when loading a config, closing a gap where `doctor` reported a false "System ready." for a config naming a backend that does not exist.
  - Config validation (`loadConfig`, `validateConfig`) now rejects a `backends[].type` that names no registered backend. A config with an unknown type parses as valid JSON and is structurally valid, but the next real command would throw `BackendUnavailableError` at backend-creation time — so `doctor` reporting all-clear undermined the diagnostic the CLI's own corrupted-config recovery points users at.
  - `doctor`'s config check now FAILS (red, exit non-zero) for an unknown backend type and names both the offending type and the valid options — the same guidance the runtime `BackendUnavailableError` gives — instead of silently passing.
  - New public `UnknownBackendTypeError` (a `ConfigValidationError` subclass) carries the offending `backendType` and the `knownTypes`. The `doctor` preflight result gains a `config-unknown-backend` error kind carrying `backendType` and `knownBackendTypes`, so a consumer can render the valid-types guidance without parsing prose.
  - The valid set is read from the backend registry (including any custom backends a consumer registered), not a hardcoded list.

- [#80](https://github.com/mike-north/vaultkeeper/pull/80) [`d511437`](https://github.com/mike-north/vaultkeeper/commit/d511437d2b8035a3f530033b80a488281c3e495d) Thanks [@mike-north](https://github.com/mike-north)! - Fix the published `.d.ts` failing to typecheck in strict consumer projects that scope `compilerOptions.types` explicitly (`TS2591: Cannot find name 'Buffer'`). `SecretAccessor.read()`, `SignRequest.data`, and `VerifyRequest.data` now resolve `Buffer` via a real `node:buffer` import plus a `/// <reference types="node" />` directive in the published rollup, instead of relying on the ambient global. `@types/node` is now declared as an optional peer dependency.

- [#82](https://github.com/mike-north/vaultkeeper/pull/82) [`2d848a7`](https://github.com/mike-north/vaultkeeper/commit/2d848a7bdccf5a04c2a99a96fd39d050cbf0c13f) Thanks [@mike-north](https://github.com/mike-north)! - Fix a security gap in `delegatedExec`: `{{secret}}` (or `{{secret:name}}`) in any `args` element was silently substituted with the raw secret value, exposing it on the process command line where it is visible to other processes via `ps` and often collected in logs and telemetry. `exec()` now throws `ExecError` if a placeholder appears in `args`, matching the existing `command`-field guardrail. Inject secrets via `env` instead.

  This is a breaking-in-practice fix: any caller that relied on placeholder substitution inside `args` will now get `ExecError` and must move the secret into `env`.

- [#107](https://github.com/mike-north/vaultkeeper/pull/107) [`9f06652`](https://github.com/mike-north/vaultkeeper/commit/9f066521adfd21042e59e7b27ea4457dec446b2b) Thanks [@mike-north](https://github.com/mike-north)! - Fix the `file` backend's default storage directory diverging from the resolved config directory. With no explicit `path` configured, secrets now land under `<configDir>/file/` — the same resolved config directory (honoring `--config-dir`/`VAULTKEEPER_CONFIG_DIR`, `~/.config/vaultkeeper` by default) that already holds `config.json` and key material — instead of the hardcoded `$HOME/.vaultkeeper/file`. An explicit `path` on the backend config still overrides this default unchanged.

  Back-compat: `retrieve`/`exists`/`delete`/`list` transparently fall back to the old `$HOME/.vaultkeeper/file` location when a secret isn't found under the new default, so secrets stored before this change remain reachable. `store` always writes to the new location going forward — nothing at the old location is migrated automatically.

- [#84](https://github.com/mike-north/vaultkeeper/pull/84) [`c521414`](https://github.com/mike-north/vaultkeeper/commit/c521414caf844cf7d740e25faf271bcb320360f5) Thanks [@mike-north](https://github.com/mike-north)! - Remove the top-level `package.json#types` field, which pointed at an API Extractor rollup (`dist/<name>-public.d.ts`) that the release pipeline never generates before `changeset publish` and was therefore absent from the published tarball. Types now resolve entirely through the conditional `exports` map, which already pointed at the real per-format `tsup` output. `@vaultkeeper/cli-test-helpers`'s `exports` conditions, which had the same stale rollup reference, now point at the real `dist/index.d.ts` / `dist/index.d.cts` files as well.

  Confirms (and now enforces via a packaging test) that only `@vaultkeeper/cli` declares the `vaultkeeper` bin — the `vaultkeeper` library package was already free of a `bin` field in this repo, but the registry had previously observed contradictory bin ownership across published versions.

- [#78](https://github.com/mike-north/vaultkeeper/pull/78) [`414bb05`](https://github.com/mike-north/vaultkeeper/commit/414bb0512743b454359d12750fb69d969cb9b4c3) Thanks [@mike-north](https://github.com/mike-north)! - Honor `BackendConfig.path` for file-based backends. Previously the documented `path` option was validated and then silently ignored: secrets always landed in the hardcoded `$HOME/.vaultkeeper/<backend>` location. The `file`, `dpapi`, and `yubikey` backends now store, retrieve, and delete secrets under the configured directory (created on demand) when `path` is set, falling back to the default location when it is not. The CLI `store` and `delete` commands inherit the fix by routing through `VaultKeeper`, which resolves the first enabled backend from config and forwards that backend's configuration.

  Config validation now rejects a whitespace-only `path` (e.g. `" "`) with the new `ConfigValidationError`, instead of silently treating it as a real storage directory.

- [#110](https://github.com/mike-north/vaultkeeper/pull/110) [`7f46237`](https://github.com/mike-north/vaultkeeper/commit/7f46237a7c5a0fd599db978604043f068ed5500b) Thanks [@mike-north](https://github.com/mike-north)! - Fix library error messages and public JSDoc that instructed users to run a bare `vaultkeeper config init` as if the CLI shipped with the `vaultkeeper` package. The library has no `bin` — the CLI ships separately as `@vaultkeeper/cli`. Remediation text in `ConfigParseError`, `ConfigValidationError`, `FilesystemError` (via `loadConfig`), and JSDoc on `defaultBackendType`, `platformNativeBackendType`, `loadConfig`, and `VaultKeeperOptions` now name `@vaultkeeper/cli` explicitly, or point to the JS-API alternative of repairing/replacing the config directly (via `config`/`configDir`). The README now states near the top that the CLI ships separately.

- [#229](https://github.com/mike-north/vaultkeeper/pull/229) [`f6e692b`](https://github.com/mike-north/vaultkeeper/commit/f6e692b9e3b4de263359f0da252bc00dc9b7767c) Thanks [@mike-north](https://github.com/mike-north)! - Fix the README "Multiple secrets in one request" example so it runs verbatim. It
  authorized `API_KEY` and `DB_PASSWORD` without storing them first, so a
  copy-pasted run threw `SecretNotFoundError` before reaching the network. The
  example is now self-contained (imports `VaultKeeper`, initializes, and stores
  each secret) and is executed against the built package in CI — not just
  type-checked — so a runtime-throwing example fails the build.

- [#77](https://github.com/mike-north/vaultkeeper/pull/77) [`26c876c`](https://github.com/mike-north/vaultkeeper/commit/26c876c4ba58eff1639cf6e2307f8c01fe5d85bd) Thanks [@mike-north](https://github.com/mike-north)! - Ship a package-specific README.md and `repository`/`homepage`/`bugs` metadata with every published package, so registry consumers get install instructions and a quick start without leaving npm.

- [#111](https://github.com/mike-north/vaultkeeper/pull/111) [`ebfcd1d`](https://github.com/mike-north/vaultkeeper/commit/ebfcd1ddfa33c62e671f185d5ebcd4461bb1c80d) Thanks [@mike-north](https://github.com/mike-north)! - Make the packaged READMEs self-contained: `vaultkeeper` and `@vaultkeeper/cli` now include a
  minimal, safe-by-default (`file` backend) example `VaultConfig`/config JSON, plus inline
  explanations of key rotation grace periods, the `trustTier` policy label, and the
  trust-on-first-use (TOFU) check that `exec` reports on every run — so the golden path no longer
  depends on fetching the unshipped repository README.

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

- [#224](https://github.com/mike-north/vaultkeeper/pull/224) [`6b6d11a`](https://github.com/mike-north/vaultkeeper/commit/6b6d11a8187c066adf7f4d1fd8672cf77fa6819d) Thanks [@mike-north](https://github.com/mike-north)! - Fix a late TOFU conflict window in `commitTrust`: if another process recorded a _different_ executable hash for the same trust-manifest namespace between the verify and commit phases, `commitTrust` reloaded the manifest but then unconditionally merged the staged hash in — silently approving a second hash for that namespace and bypassing the TOFU-conflict record-nothing rule. `commitTrust` now re-classifies the staged entry against the freshly reloaded manifest: an already-trusted hash stays a no-op, an empty namespace still merges, but a namespace whose approved hashes don't include the staged one now throws `IdentityMismatchError` and writes nothing. Mirrors the Rust `PendingTrust::commit` fix.

- [#128](https://github.com/mike-north/vaultkeeper/pull/128) [`8ded257`](https://github.com/mike-north/vaultkeeper/commit/8ded257614332f9faf758b0a7c5e5c711528d8e3) Thanks [@mike-north](https://github.com/mike-north)! - Replace the guessed "TypeScript 5.x" README note with the actually-tested range: a CI matrix (`packages/vaultkeeper/test/e2e/consumer-typecheck.test.ts`) now typechecks the shipped `.d.ts` of `vaultkeeper`, `@vaultkeeper/test-helpers`, and `@vaultkeeper/cli-test-helpers` against pinned TypeScript 5.0.4, 5.9.3, 6.0.3, and 7.0.2 compilers — all pass, so both READMEs now state a tested 5.0.4–7.0.2 range instead of a narrower guess.

- [#186](https://github.com/mike-north/vaultkeeper/pull/186) [`a4a6cb7`](https://github.com/mike-north/vaultkeeper/commit/a4a6cb7809591237eb46027518681ffe5943f174) Thanks [@mike-north](https://github.com/mike-north)! - Validate the signing/verification algorithm before parsing key material in `VaultKeeper.verify()` (and the internal signing path). A disallowed algorithm (e.g. `md5`) now throws `InvalidAlgorithmError` unconditionally and synchronously, as documented — even when the supplied key material is also malformed. Previously a malformed public key short-circuited to `false` and silently skipped the algorithm guard, so callers relying on `try`/`catch` for `InvalidAlgorithmError` were not protected when key material was attacker-controlled.

- [#176](https://github.com/mike-north/vaultkeeper/pull/176) [`f2baa86`](https://github.com/mike-north/vaultkeeper/commit/f2baa86b9f329a5a557f27c5985a3950c351e7b5) Thanks [@mike-north](https://github.com/mike-north)! - Close the `@vaultkeeper/wasm` getting-started and API-reference documentation gaps.
  - The WASM quick start now leads with an ESM-setup callout. `@vaultkeeper/wasm` is ESM-only (no CommonJS fallback), so a copy-paste of the snippet into a default `npm init -y` (CommonJS) project previously failed with `SyntaxError: Cannot use import statement outside a module`. The callout documents adding `"type": "module"` first, so the documented steps now succeed from a fresh project.
  - `SetupOptions.executablePath` JSDoc (and the generated API reference) now states positively that this WASM SDK records the path as a claim label and performs no trust-on-first-use (TOFU) verification — no hashing, manifest check, or throw on a changed/nonexistent path — unlike the TypeScript `vaultkeeper` library's `VaultKeeper.setup()`. Cross-references the behavioral follow-up tracked separately.
  - The `vaultkeeper` README Trust-tiers section now scopes its "requires an explicit executable-trust choice / never silently skips verification" guarantee to the TypeScript library, and notes that `@vaultkeeper/wasm` records `executablePath` as a claim label without running TOFU verification.
  - `SetupOptions.backendType` is now documented as a claim label only (recorded in the token's `bkd` claim) that does not select or route through a functional backend, mirroring the claim-label framing of `executablePath`.

## 0.6.0

### Minor Changes

- [`5bbff5a`](https://github.com/mike-north/vaultkeeper/commit/5bbff5a7c6129a5240b3307c6915e4957b3889c1) Thanks [@mike-north](https://github.com/mike-north)! - Improve developer experience: wrap ENOENT spawn errors in PluginNotFoundError, add store() and delete() convenience methods to VaultKeeper, clarify setup() JSDoc, and add missing @public tag on InvalidAlgorithmError

- [`5bbff5a`](https://github.com/mike-north/vaultkeeper/commit/5bbff5a7c6129a5240b3307c6915e4957b3889c1) Thanks [@mike-north](https://github.com/mike-north)! - Standardize authorize() return type to use vaultResponse (matching exec/fetch/sign), accept RunDoctorOptions in VaultKeeper.doctor(), and include reason in required dependency error messages

- [#54](https://github.com/mike-north/vaultkeeper/pull/54) [`a7540d1`](https://github.com/mike-north/vaultkeeper/commit/a7540d1b2198dceace73c1e1abba2dcd0f565f03) Thanks [@mike-north](https://github.com/mike-north)! - Add ExecError, InvalidTokenError, and AccessorConsumedError for precise error handling; validate secret names are non-empty; detect {{secret}} in exec command field; update README quick start with store() step

- [#54](https://github.com/mike-north/vaultkeeper/pull/54) [`a7540d1`](https://github.com/mike-north/vaultkeeper/commit/a7540d1b2198dceace73c1e1abba2dcd0f565f03) Thanks [@mike-north](https://github.com/mike-north)! - Add multi-secret support for delegated exec and fetch via `SecretTokenMap` and `{{secret:name}}` placeholders.

## 0.5.3

### Patch Changes

- [#46](https://github.com/mike-north/vaultkeeper/pull/46) [`a037cd6`](https://github.com/mike-north/vaultkeeper/commit/a037cd6e540ede350bc8a681a5ebbea8296a3793) Thanks [@mike-north](https://github.com/mike-north)! - Doctor checks are now scoped to the backends configured in vault config. System dependency checks (`secret-tool`, `security`, `powershell`) are only treated as required when the corresponding backend is enabled, eliminating false positives on systems that use only the file backend or a subset of platform backends. Conversely, `op` and `ykman` are now treated as required when the `1password` or `yubikey` backends are explicitly enabled. When no `backends` config is provided, all platform-default checks remain required (backward-compatible behavior).

## 0.5.2

### Patch Changes

- [#43](https://github.com/mike-north/vaultkeeper/pull/43) [`f0fe162`](https://github.com/mike-north/vaultkeeper/commit/f0fe16247ebcfc33ad0dd65a57695a101ca07b61) Thanks [@mike-north](https://github.com/mike-north)! - Accept string-typed `trustTier` values (`"1"`, `"2"`, `"3"`) in config files, fixing compatibility with configs generated by the Rust CLI.

- [#44](https://github.com/mike-north/vaultkeeper/pull/44) [`3b5868f`](https://github.com/mike-north/vaultkeeper/commit/3b5868f676e6b4131e5d99c244246c7cbb325845) Thanks [@mike-north](https://github.com/mike-north)! - Fix error type correctness: `InMemoryBackend` now throws `SecretNotFoundError` (not plain `Error`), exceeding a token's use limit throws `UsageLimitExceededError` (not `TokenRevokedError`), and double-reading a `SecretAccessor` throws a descriptive error instead of a raw Proxy `TypeError`.

## 0.5.1

### Patch Changes

- [#39](https://github.com/mike-north/vaultkeeper/pull/39) [`003e497`](https://github.com/mike-north/vaultkeeper/commit/003e4972c6bf1c4b39e838ed32346a84e4396bee) Thanks [@mike-north](https://github.com/mike-north)! - Export `runDoctor`, `RunDoctorOptions`, and `Platform` as public API. Fix `setup()` JSDoc to accurately describe its behavior (retrieves, not stores). Add README sections for storing secrets, testing, platforms, and missing error types.

## 1.0.1

### Patch Changes

- [#20](https://github.com/mike-north/vaultkeeper/pull/20) [`c65c107`](https://github.com/mike-north/vaultkeeper/commit/c65c1076802dcc5e2710c47fd60e3f1771858fe1) Thanks [@mike-north](https://github.com/mike-north)! - Add VAULTKEEPER_CONFIG_DIR env var for test isolation and introduce @vaultkeeper/cli-test-helpers package with reusable CLI test infrastructure

- [#23](https://github.com/mike-north/vaultkeeper/pull/23) [`3f95e3b`](https://github.com/mike-north/vaultkeeper/commit/3f95e3b954cb6f046e34f2155da9ff945d47c16e) Thanks [@mike-north](https://github.com/mike-north)! - Fix built-in backends not registered at module load (issue #21)

  BackendRegistry shipped empty because no built-in backends called
  `BackendRegistry.register()`. Adds a side-effect module
  (`register-builtins.ts`) imported from the package entry point so all
  six built-in backends (file, keychain, dpapi, secret-tool, 1password,
  yubikey) are available immediately after `import 'vaultkeeper'`.

  Also updates `BackendFactory` to accept an optional `BackendConfig`,
  allowing `VaultKeeper.init()` to forward per-backend configuration
  (e.g. 1Password vault ID and access mode) through the registry.

## 1.0.0

### Major Changes

- [#19](https://github.com/mike-north/vaultkeeper/pull/19) [`c0d36c5`](https://github.com/mike-north/vaultkeeper/commit/c0d36c5f5bdc7848574863514bfe53e23ce83d42) Thanks [@mike-north](https://github.com/mike-north)! - Migrate 1Password backend from `op` CLI to `@1password/sdk`

  Breaking change: the 1Password backend now requires the `@1password/sdk` package and either the 1Password desktop app (for biometric auth via `DesktopAuth`) or a service account token (for headless CI/CD). The `op` CLI is no longer used.

  New per-credential access modes:
  - **Session mode** (default): SDK client is created once on first use and cached for the lifetime of the process. A 30-second timeout guards against the SDK hanging during authentication (known beta bug).
  - **Per-access mode**: fresh biometric prompt for every secret retrieval via child process isolation. Only available with desktop auth (not service account tokens).

  Setup now collects account name, vault, and access mode preference.

### Minor Changes

- [#15](https://github.com/mike-north/vaultkeeper/pull/15) [`5353518`](https://github.com/mike-north/vaultkeeper/commit/535351866ef9cb4e77edb9b2b757911e74b3b402) Thanks [@mike-north](https://github.com/mike-north)! - Add delegated signing, static verification, and backend setup protocol to VaultKeeper.

  **Signing & Verification:**
  `VaultKeeper.sign()` signs arbitrary data using a private key stored in the vault, returning a base64-encoded signature without exposing the key to the caller. `VaultKeeper.verify()` is a static method that verifies a signature against a public key and requires no VaultKeeper instance. New exported types: `SignRequest`, `SignResult`, `VerifyRequest`. New error: `InvalidAlgorithmError` for disallowed algorithm overrides.

  **Backend Setup Protocol:**
  Adds an async-generator-based interactive setup protocol for backend configuration. Each backend that requires user input implements a setup generator that yields `SetupQuestion` objects; consumers render them and send answers back via `generator.next(answer)`. Includes discovery modules for 1Password, macOS Keychain, and YubiKey. New exported types: `SetupQuestion`, `SetupChoice`, `SetupResult`, `BackendSetupFactory`. New `BackendRegistry` methods: `registerSetup()`, `getSetup()`, `hasSetup()`. `BackendConfig` gains an `options` field for persisting setup results.

## 0.4.0

### Minor Changes

- [#13](https://github.com/mike-north/vaultkeeper/pull/13) [`a1d2e57`](https://github.com/mike-north/vaultkeeper/commit/a1d2e57fe3b2132d63755c31acc332b90ae7a799) Thanks [@mike-north](https://github.com/mike-north)! - Add delegated signing and static verification to VaultKeeper.

  `VaultKeeper.sign()` signs arbitrary data using a private key stored in the vault, returning a base64-encoded signature without exposing the key to the caller. `VaultKeeper.verify()` is a static method that verifies a signature against a public key and requires no VaultKeeper instance. New exported types: `SignRequest`, `SignResult`, `VerifyRequest`.

## 0.3.0

### Minor Changes

- [#10](https://github.com/mike-north/vaultkeeper/pull/10) [`a000092`](https://github.com/mike-north/vaultkeeper/commit/a000092848e94e130893d145d07a8b8bf6fc1ead) Thanks [@mike-north](https://github.com/mike-north)! - Add `BackendRegistry.getAvailableTypes()` for discovering which secret backends are available on the current system.

- [#9](https://github.com/mike-north/vaultkeeper/pull/9) [`c2c4e8c`](https://github.com/mike-north/vaultkeeper/commit/c2c4e8cfd94e624b4ad7dfd2f3b22a6046d91c8e) Thanks [@mike-north](https://github.com/mike-north)! - Add `ListableBackend` interface with `list()` method for enumerating stored secrets, implemented on all backends. Add `isListableBackend()` type guard. `InMemoryBackend` now also implements `ListableBackend`.

### Patch Changes

- [#11](https://github.com/mike-north/vaultkeeper/pull/11) [`7398ff6`](https://github.com/mike-north/vaultkeeper/commit/7398ff6352b8d3e39e562ace50b8caa8ef998882) Thanks [@mike-north](https://github.com/mike-north)! - Fix YubiKey backend encryption: replace AES-256-CBC (openssl CLI) with AES-256-GCM (Node.js crypto) per project security policy. Legacy CBC-encrypted files are detected with a clear migration error.

## 0.2.0

### Minor Changes

- [#6](https://github.com/mike-north/vaultkeeper/pull/6) [`1f1412c`](https://github.com/mike-north/vaultkeeper/commit/1f1412c7b76c7810b395df4b9de44ebe21a16188) Thanks [@mike-north](https://github.com/mike-north)! - Reduce public API surface from ~80 to ~33 symbols. Internal implementation details (JWE plumbing, KeyManager, doctor checks, identity/trust helpers, access helpers, config helpers, backend classes) are no longer exported from the package entrypoint. All internalized symbols are marked `@internal`; while they may still be reachable via deep imports in workspace/monorepo builds, they are not part of the published package's supported public API.

## 0.1.0

### Minor Changes

- [#1](https://github.com/mike-north/vaultkeeper/pull/1) [`7e9c1f5`](https://github.com/mike-north/vaultkeeper/commit/7e9c1f5b448ea97862aee607898f1ff84081519f) Thanks [@mike-north](https://github.com/mike-north)! - Convert to pnpm workspace monorepo and add test-helpers package
  - Restructured as a pnpm workspace with `packages/vaultkeeper` and `packages/test-helpers`
  - Added `@vaultkeeper/test-helpers` package providing `InMemoryBackend` and `TestVault` for fast, hermetic tests
  - Shared TypeScript config via `tsconfig.base.json`, shared ESLint config at workspace root
  - Added vitest workspace configuration for cross-package test execution
  - Added changesets for version and changelog management
