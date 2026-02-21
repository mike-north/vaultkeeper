# vaultkeeper — Agent Instructions

## Project overview

vaultkeeper is a TypeScript library providing unified, policy-enforced secret storage across OS credential backends. It is ESM-first with dual CJS/ESM output. The public API is type-checked and validated by API Extractor before each release.

## Package manager

Always use `pnpm`. Never use `npm` or `npx`.

- Run scripts: `pnpm <script>`
- Execute binaries: `pnpm exec <binary>` (e.g. `pnpm exec tsc`)
- One-off packages: `pnpm dlx <package>` (not `npx`)
- TypeScript compiler: `pnpm exec tsc` — never `npx tsc` or `pnpm dlx tsc`

## Key scripts

| Script | Purpose |
|--------|---------|
| `pnpm build` | Compile with `tsup` (ESM + CJS dual output to `dist/`) |
| `pnpm clean` | Remove `dist/` |
| `pnpm test` | Run all tests once with vitest |
| `pnpm test:watch` | Run tests in watch mode |
| `pnpm check` | Run typecheck + lint + API report validation (all three must pass) |
| `pnpm check:typecheck` | `tsc --noEmit` |
| `pnpm check:lint-ts` | `eslint .` |
| `pnpm check:api-report` | `api-extractor run` (validates against committed report) |
| `pnpm generate:api-report` | `api-extractor run --local` (updates the committed report) |

Run `pnpm check` before declaring any implementation task complete.

When the public API surface changes (new exports, changed signatures, removed types), run `pnpm generate:api-report` and commit the updated files in `api-report/`.

## Source layout

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

## Test layout

```
test/
  unit/              # Pure unit tests, dependencies mocked
  integration/       # Real component boundaries wired together
  e2e/               # Full assembled flow tests
  helpers/           # Shared test fixtures and factory functions
```

Tests use vitest. Test files match `test/**/*.test.ts`. Coverage is collected with `v8`.

## TypeScript configuration

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

ESLint uses `typescript-eslint` with `strictTypeChecked` + `stylisticTypeChecked`. Formatting is handled by Prettier, not ESLint (`eslint-config-prettier` is applied last).

Additional plugins active: `eslint-plugin-n` (Node.js built-in usage) and `eslint-plugin-security`.

Key rules to respect:

- `@typescript-eslint/consistent-type-assertions: { assertionStyle: 'never' }` — **no `as` casts anywhere**. If you need to assert a type, redesign the code so the type flows correctly.
- `@typescript-eslint/no-explicit-any: error` — no `any`.
- All `no-unsafe-*` rules are errors — do not suppress them without a documented reason.
- `@typescript-eslint/no-unused-vars` — underscore-prefix (`_name`) to intentionally ignore.
- `no-plusplus: off` — `++` and `--` are allowed.

When ESLint reports an error, fix the code — do not add `// eslint-disable` comments unless there is no other option, and document the reason when you do.

## API Extractor

API Extractor v7 (`@microsoft/api-extractor`) is configured in `api-extractor.json`. It generates a `.d.ts` rollup at `dist/vaultkeeper-public.d.ts` (referenced by `package.json#types`).

Workflow:
1. `pnpm build` — produces `dist/*.d.ts` source files
2. `pnpm generate:api-report` — updates `api-report/vaultkeeper.api.md`
3. Commit `api-report/` when the public API changes
4. `pnpm check:api-report` (no `--local`) validates the committed report matches the built output; this runs in CI

Every exported symbol in `src/index.ts` must have a `@public` or `@packageDocumentation` JSDoc tag (or be marked `@internal` / `@alpha` / `@beta` if not yet stable).

## Conventions

### Errors

All errors extend `VaultError` (defined in `src/errors.ts`). When adding a new error class:
- Extend the closest existing base (e.g. `VaultError` directly if no better parent exists)
- Set `this.name` in the constructor to match the class name
- Add strongly-typed extra fields for machine-readable context
- Export from `src/index.ts`

Never throw plain `Error` objects — always use a typed subclass from the error hierarchy.

### Backends

All backends implement `SecretBackend` from `src/backend/types.ts`. Register new backends with `BackendRegistry.register(type, factory)`. The factory must be a zero-argument function returning a `SecretBackend` instance.

Plugin backends (1Password, YubiKey) are flagged with `plugin: true` in `BackendConfig`.

### JWE tokens

Tokens are compact JWE strings (using the `jose` library). The encrypted payload is `VaultClaims`. Keys are managed by `KeyManager`. Do not roll a custom encryption scheme — use the existing `createToken` / `decryptToken` API in `src/jwe/`.

### Access patterns

- Delegated fetch/exec: substitute `{{secret}}` placeholders; the raw secret must never appear in a return value
- Controlled direct: use `createSecretAccessor` — wraps the secret in an auto-zeroing `Buffer` accessible only through a one-time `read()` callback

### Security rules

- Never pass secrets as CLI arguments — use stdin or environment variables
- Use AES-256-GCM for any symmetric encryption — never AES-CBC
- Zero `Buffer` instances containing secrets after use
- Treat `VaultClaims.val` as the only location where the raw secret travels in memory; keep that path short

## Dependency notes

The only runtime dependency is `jose` (JWE/JWT). Everything else is dev-only. Do not add runtime dependencies without discussion — the library is intended to be lean.
