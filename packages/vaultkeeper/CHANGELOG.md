# vaultkeeper

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
