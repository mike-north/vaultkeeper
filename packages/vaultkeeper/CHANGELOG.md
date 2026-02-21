# vaultkeeper

## 0.1.0

### Minor Changes

- [#1](https://github.com/mike-north/vaultkeeper/pull/1) [`7e9c1f5`](https://github.com/mike-north/vaultkeeper/commit/7e9c1f5b448ea97862aee607898f1ff84081519f) Thanks [@mike-north](https://github.com/mike-north)! - Convert to pnpm workspace monorepo and add test-helpers package
  - Restructured as a pnpm workspace with `packages/vaultkeeper` and `packages/test-helpers`
  - Added `@vaultkeeper/test-helpers` package providing `InMemoryBackend` and `TestVault` for fast, hermetic tests
  - Shared TypeScript config via `tsconfig.base.json`, shared ESLint config at workspace root
  - Added vitest workspace configuration for cross-package test execution
  - Added changesets for version and changelog management
