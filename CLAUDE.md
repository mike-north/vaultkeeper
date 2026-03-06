# vaultkeeper — Agent Instructions

## Project overview

vaultkeeper is a polyglot monorepo (TypeScript + Rust) providing unified, policy-enforced secret storage across OS credential backends. It uses pnpm workspaces for TypeScript packages and a Cargo workspace for Rust crates, with Nx orchestrating dependency-graph-aware builds across both.

### TypeScript packages (`packages/`)

- **`vaultkeeper`** (`packages/vaultkeeper/`) — TypeScript library: ESM-first with dual CJS/ESM output. The public API is type-checked and validated by API Extractor.
- **`@vaultkeeper/cli`** (`packages/cli/`) — TypeScript CLI: `npx vaultkeeper` with lazy-loaded subcommands.
- **`@vaultkeeper/wasm`** (`packages/vaultkeeper-wasm/`) — WASM-backed SDK for Node.js. Wraps the Rust core compiled to WebAssembly with a Node.js host platform bridge.
- **`@vaultkeeper/test-helpers`** (`packages/test-helpers/`) — Test utilities: InMemoryBackend and TestVault for fast, hermetic tests.
- **`@vaultkeeper/cli-test-helpers`** (`packages/cli-test-helpers/`) — CLI test harness: creates isolated temp config dirs for subprocess testing.
- **`@vaultkeeper/cli-tests`** (`packages/cli-tests/`) — CLI user acceptance tests and conformance tests against the Rust binary.

### Rust crates (`crates/`)

- **`vaultkeeper-core`** — Core library: all business logic, crypto (JWE, AES-256-GCM), backends, key management, identity, doctor checks. Platform-agnostic via `HostPlatform` trait.
- **`vaultkeeper-cli`** — Native CLI binary using clap. Provides `NativeHostPlatform` impl.
- **`vaultkeeper-wasm`** — wasm-bindgen wrapper over core. Compiled with `wasm-pack --target nodejs`.
- **`vaultkeeper-conformance`** — Data-driven conformance test definitions. Exports cases as JSON for both Rust and JS test runners.

## Package manager

Always use `pnpm`. Never use `npm` or `npx`.

- Run scripts: `pnpm <script>`
- Execute binaries: `pnpm exec <binary>` (e.g. `pnpm exec tsc`)
- One-off packages: `pnpm dlx <package>` (not `npx`)
- TypeScript compiler: `pnpm exec tsc` — never `npx tsc` or `pnpm dlx tsc`

## Workspace structure

```
vaultkeeper/
├── Cargo.toml              (Cargo workspace root)
├── pnpm-workspace.yaml     (pnpm workspace root)
├── package.json            (private workspace root — Nx scripts)
├── nx.json                 (Nx orchestration config)
├── tsconfig.base.json      (shared TS compiler options)
├── eslint.config.ts        (shared lint config)
├── vitest.workspace.ts     (vitest workspace config)
├── crates/
│   ├── vaultkeeper-core/       (Rust core library)
│   ├── vaultkeeper-cli/        (Rust native CLI)
│   ├── vaultkeeper-wasm/       (Rust WASM bindings)
│   └── vaultkeeper-conformance/ (conformance test data)
├── packages/
│   ├── vaultkeeper/            (TS library)
│   ├── cli/                    (TS CLI)
│   ├── vaultkeeper-wasm/       (WASM SDK — TS wrapper + committed .wasm)
│   ├── test-helpers/           (test utilities)
│   ├── cli-test-helpers/       (CLI test harness)
│   └── cli-tests/              (CLI UATs + conformance runner)
```

## Build orchestration (Nx)

All workspace-level scripts use Nx for dependency-graph-aware execution with caching. Nx understands inter-package dependencies and runs tasks in correct order.

**Never invoke `nx` directly** — use the npm scripts in root `package.json`.

### Workspace-level scripts

| Script | Purpose |
|--------|---------|
| `pnpm build` | Build all TS packages (Nx resolves dependency order) |
| `pnpm clean` | Clean all packages |
| `pnpm test` | Run all tests across all packages |
| `pnpm test:watch` | Run tests in watch mode (vitest workspace) |
| `pnpm check` | Run typecheck + lint + API report validation |
| `pnpm check:typecheck` | `tsc --noEmit` in all packages |
| `pnpm check:lint-ts` | `eslint .` in all packages |
| `pnpm check:api-report` | Validate API reports |
| `pnpm generate:api-report` | Update API reports |

### Rust builds

Rust builds are separate from Nx (Cargo manages its own dependency graph):

| Command | Purpose |
|---------|---------|
| `cargo build` | Build all Rust crates |
| `cargo test` | Run all Rust tests (130 tests) |
| `cargo clippy` | Lint Rust code |
| `wasm-pack build --target nodejs crates/vaultkeeper-wasm` | Build WASM module |

The WASM output (`packages/vaultkeeper-wasm/wasm/`) is committed to git so TypeScript builds work without wasm-pack installed.

### Package-level (run with `--filter`)

Use `pnpm --filter <name>` to target a specific package:
- `pnpm --filter vaultkeeper build`
- `pnpm --filter @vaultkeeper/wasm test`

Run `pnpm check` before declaring any implementation task complete.

When the public API surface changes, run `pnpm generate:api-report` and commit the updated `api-report/` files.

## Source layout (packages/vaultkeeper)

```
src/
  index.ts           # Public re-exports — all public API must flow through here
  vault.ts           # VaultKeeper class — main entry point
  types.ts           # Shared interfaces and type aliases
  errors.ts          # Error hierarchy (all extend VaultError)
  config.ts          # Config loading and validation
  backend/           # SecretBackend implementations and registry
  jwe/               # JWE token creation, decryption, and blocklist
  keys/              # KeyManager and key rotation logic
  doctor/            # Preflight checks (runDoctor and per-dependency checks)
  identity/          # Executable trust verification, TOFU manifest, CapabilityToken
  access/            # delegatedFetch, delegatedExec, createSecretAccessor
  util/              # Platform detection and shared utilities
```

## Source layout (crates/vaultkeeper-core)

```
src/
  lib.rs             # Crate root — re-exports public API
  vault.rs           # VaultKeeper orchestrator
  types.rs           # Shared types (VaultConfig, DevelopmentMode, etc.)
  errors.rs          # Error hierarchy (VaultError via thiserror)
  config/            # Config loading and validation
  backend/           # SecretBackend trait, FileBackend, InMemoryBackend, registry
  jwe/               # JWE token create/decrypt (AES-256-GCM, compatible with jose)
  keys/              # KeyManager, rotation, grace periods
  identity/          # SHA-256 hashing, TOFU manifest, trust tiers
  doctor/            # Preflight check types and logic
  access/            # SecretAccessor re-export; higher-level patterns live in TS SDK
  util/              # Time utilities
```

## Test layout

### TypeScript tests

```
packages/vaultkeeper/test/
  unit/              # Pure unit tests, dependencies mocked
  integration/       # Real component boundaries wired together
  e2e/               # Full assembled flow tests

packages/cli-tests/test/
  e2e/               # CLI user acceptance tests (subprocess)
  conformance/       # Data-driven tests against the Rust CLI binary
```

Tests use vitest (except `@vaultkeeper/wasm` which uses `node:test`). Coverage collected with `v8`.

### Rust tests

- `crates/vaultkeeper-core/tests/` — unit tests (47 tests)
- `crates/vaultkeeper-cli/tests/` — CLI integration tests (8 tests)
- `crates/vaultkeeper-conformance/tests/` — conformance runner (19 cases)

### Conformance testing

Both CLIs (Rust native and TS) are tested against the same data-driven test cases:
1. Cases defined in `crates/vaultkeeper-conformance/src/lib.rs`
2. Exported as JSON via `cargo run -p export-conformance`
3. JS runner in `packages/cli-tests/test/conformance/` loads `cases.json` and tests the Rust binary
4. Rust runner in `crates/vaultkeeper-conformance/tests/` tests the same binary directly
5. TS CLI tested via `packages/cli-tests/test/e2e/` (subprocess tests against `@vaultkeeper/cli`)

The JS conformance runner skips gracefully (`describe.skipIf`) when the Rust binary isn't available.

## TypeScript configuration

Shared compiler options live in `tsconfig.base.json` at the root. Each package extends it.

- `target`: ES2022
- `module` / `moduleResolution`: NodeNext
- `strict`: true — all strictness flags enabled
- `noUncheckedIndexedAccess`: true — array/index access returns `T | undefined`
- `exactOptionalPropertyTypes`: true — do not assign `undefined` to optional properties
- `verbatimModuleSyntax`: true — use `import type` for type-only imports
- `esModuleInterop`: false — do not add synthetic default imports
- `allowSyntheticDefaultImports`: false — do not allow synthetic defaults
- `noEmitOnError`: true — build fails on type errors

Do not add `skipLibCheck: true` without explicit approval. Do not enable `esModuleInterop` or `allowSyntheticDefaultImports`.

## ESLint configuration

ESLint uses `typescript-eslint` with `strictTypeChecked` + `stylisticTypeChecked`. Formatting is handled by Prettier, not ESLint (`eslint-config-prettier` is applied last). The config lives at the workspace root and applies to all packages.

Additional plugins active: `eslint-plugin-n` (Node.js built-in usage) and `eslint-plugin-security`.

Key rules to respect:

- `@typescript-eslint/consistent-type-assertions: { assertionStyle: 'never' }` — **no `as` casts anywhere**. If you need to assert a type, redesign the code so the type flows correctly.
- `@typescript-eslint/no-explicit-any: error` — no `any`.
- All `no-unsafe-*` rules are errors — do not suppress them without a documented reason.
- `@typescript-eslint/no-unused-vars` — underscore-prefix (`_name`) to intentionally ignore.
- `no-plusplus: off` — `++` and `--` are allowed.

When ESLint reports an error, fix the code — do not add `// eslint-disable` comments unless there is no other option, and document the reason when you do.

Generated files in `**/wasm/**` (wasm-pack output) are excluded from linting.

## API Extractor

API Extractor v7 (`@microsoft/api-extractor`) is configured per-package in `api-extractor.json`. Each package generates its own `.d.ts` rollup and API report.

Workflow:
1. `pnpm build` — produces `dist/*.d.ts` source files
2. `pnpm generate:api-report` — updates API reports in all packages
3. Commit `api-report/` when the public API changes
4. `pnpm check:api-report` (no `--local`) validates the committed report matches the built output; this runs in CI

Every exported symbol in a package's `src/index.ts` must have a `@public` or `@packageDocumentation` JSDoc tag (or be marked `@internal` / `@alpha` / `@beta` if not yet stable).

## Conventions

### Errors

All errors extend `VaultError` (defined in `packages/vaultkeeper/src/errors.ts`). When adding a new error class:
- Extend the closest existing base (e.g. `VaultError` directly if no better parent exists)
- Set `this.name` in the constructor to match the class name
- Add strongly-typed extra fields for machine-readable context
- Export from `src/index.ts`

Never throw plain `Error` objects — always use a typed subclass from the error hierarchy.

### Backends

All backends implement `SecretBackend` from `packages/vaultkeeper/src/backend/types.ts`. Register new backends with `BackendRegistry.register(type, factory)`. The factory must be a zero-argument function returning a `SecretBackend` instance.

Plugin backends (1Password, YubiKey) are flagged with `plugin: true` in `BackendConfig`.

### JWE tokens

Tokens are compact JWE strings. The TS library uses the `jose` npm package; the Rust core uses `aes-gcm` + `base64ct` directly (wire-compatible). The encrypted payload is `VaultClaims`. Keys are managed by `KeyManager`. Do not roll a custom encryption scheme — use the existing token APIs.

### Rust/TS interop

- Config JSON uses **camelCase** field names, enforced via `#[serde(rename_all = "camelCase")]`
- `TrustTier` serializes as string numbers: `"1"`, `"2"`, `"3"`
- VaultClaims fields use serde renames: `use_limit` → JSON `use`, `reference` → JSON `ref`
- Both CLIs have identical command surfaces and output formats

### Access patterns

- Delegated fetch/exec: substitute `{{secret}}` placeholders; the raw secret must never appear in a return value
- Controlled direct: use `createSecretAccessor` — wraps the secret in an auto-zeroing `Buffer` accessible only through a one-time `read()` callback

### Security rules

- Never pass secrets as CLI arguments — use stdin or environment variables
- Use AES-256-GCM for any symmetric encryption — never AES-CBC
- Zero `Buffer` instances containing secrets after use
- Treat `VaultClaims.val` as the only location where the raw secret travels in memory; keep that path short

## Dependency notes

The only runtime dependency for `vaultkeeper` (TS) is `jose` (JWE/JWT). The `@vaultkeeper/wasm` package has no runtime npm dependencies — it ships a committed `.wasm` binary. The `@vaultkeeper/test-helpers` package depends on `vaultkeeper` via `workspace:*`. Everything else is dev-only. Do not add runtime dependencies without discussion.
