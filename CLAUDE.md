# vaultkeeper — Agent Instructions

## Project overview

vaultkeeper is a pnpm workspace monorepo containing two packages:

- **`vaultkeeper`** (`packages/vaultkeeper/`) — TypeScript library providing unified, policy-enforced secret storage across OS credential backends. ESM-first with dual CJS/ESM output. The public API is type-checked and validated by API Extractor.
- **`@vaultkeeper/test-helpers`** (`packages/test-helpers/`) — Test utilities for vaultkeeper consumers, including an in-memory backend and a pre-configured `TestVault` for fast, hermetic tests.

## Package manager

Always use `pnpm`. Never use `npm` or `npx`.

- Run scripts: `pnpm <script>`
- Execute binaries: `pnpm exec <binary>` (e.g. `pnpm exec tsc`)
- One-off packages: `pnpm dlx <package>` (not `npx`)
- TypeScript compiler: `pnpm exec tsc` — never `npx tsc` or `pnpm dlx tsc`

## Workspace structure

```
vaultkeeper/
├── pnpm-workspace.yaml
├── package.json            (private workspace root)
├── tsconfig.base.json      (shared compiler options)
├── eslint.config.ts        (shared lint config)
├── vitest.workspace.ts     (vitest workspace config)
├── packages/
│   ├── vaultkeeper/        (main library)
│   │   ├── package.json
│   │   ├── tsconfig.json
│   │   ├── tsup.config.ts
│   │   ├── api-extractor.json
│   │   ├── api-report/
│   │   ├── src/
│   │   └── test/
│   └── test-helpers/       (@vaultkeeper/test-helpers)
│       ├── package.json
│       ├── tsconfig.json
│       ├── tsup.config.ts
│       ├── api-extractor.json
│       ├── api-report/
│       ├── src/
│       └── test/
```

## Key scripts

### Workspace-level (run from root)

| Script | Purpose |
|--------|---------|
| `pnpm build` | Build all packages (recursive) |
| `pnpm clean` | Clean all packages (recursive) |
| `pnpm test` | Run all tests across all packages |
| `pnpm test:watch` | Run tests in watch mode (vitest workspace) |
| `pnpm check` | Run typecheck + lint + API report validation across all packages |
| `pnpm check:typecheck` | `tsc --noEmit` in all packages |
| `pnpm check:lint-ts` | `eslint .` in all packages |
| `pnpm check:api-report` | Validate API reports in all packages |
| `pnpm generate:api-report` | Update API reports in all packages |

### Package-level (run with `--filter`)

Use `pnpm --filter <name>` to target a specific package:
- `pnpm --filter vaultkeeper build`
- `pnpm --filter @vaultkeeper/test-helpers test`

Each package has the same script names: `build`, `clean`, `test`, `check`, `check:typecheck`, `check:lint-ts`, `check:api-report`, `generate:api-report`.

Run `pnpm check` before declaring any implementation task complete.

When the public API surface changes (new exports, changed signatures, removed types), run `pnpm generate:api-report` and commit the updated files in `api-report/`.

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

## Source layout (packages/test-helpers)

```
src/
  index.ts              # Public exports: InMemoryBackend, TestVault
  in-memory-backend.ts  # In-memory SecretBackend implementation
  test-vault.ts         # Pre-configured VaultKeeper for tests
```

## Test layout

Each package has its own `test/` directory:

```
packages/vaultkeeper/test/
  unit/              # Pure unit tests, dependencies mocked
  integration/       # Real component boundaries wired together
  e2e/               # Full assembled flow tests
  helpers/           # Shared test fixtures and factory functions

packages/test-helpers/test/
  unit/              # Tests for InMemoryBackend and TestVault
```

Tests use vitest. Test files match `test/**/*.test.ts`. Coverage is collected with `v8`.

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

Tokens are compact JWE strings (using the `jose` library). The encrypted payload is `VaultClaims`. Keys are managed by `KeyManager`. Do not roll a custom encryption scheme — use the existing `createToken` / `decryptToken` API in `packages/vaultkeeper/src/jwe/`.

### Access patterns

- Delegated fetch/exec: substitute `{{secret}}` placeholders; the raw secret must never appear in a return value
- Controlled direct: use `createSecretAccessor` — wraps the secret in an auto-zeroing `Buffer` accessible only through a one-time `read()` callback

### Security rules

- Never pass secrets as CLI arguments — use stdin or environment variables
- Use AES-256-GCM for any symmetric encryption — never AES-CBC
- Zero `Buffer` instances containing secrets after use
- Treat `VaultClaims.val` as the only location where the raw secret travels in memory; keep that path short

## Dependency notes

The only runtime dependency for `vaultkeeper` is `jose` (JWE/JWT). The `@vaultkeeper/test-helpers` package depends on `vaultkeeper` via `workspace:*`. Everything else is dev-only. Do not add runtime dependencies without discussion — the library is intended to be lean.
