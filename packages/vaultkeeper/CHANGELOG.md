# vaultkeeper

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
