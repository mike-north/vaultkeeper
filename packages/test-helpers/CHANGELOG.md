# @vaultkeeper/test-helpers

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
