# @vaultkeeper/test-helpers

## 0.2.2

### Patch Changes

- Updated dependencies [[`5353518`](https://github.com/mike-north/vaultkeeper/commit/535351866ef9cb4e77edb9b2b757911e74b3b402)]:
  - vaultkeeper@0.5.0

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
