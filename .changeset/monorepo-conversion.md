---
"vaultkeeper": minor
"@vaultkeeper/test-helpers": minor
---

Convert to pnpm workspace monorepo and add test-helpers package

- Restructured as a pnpm workspace with `packages/vaultkeeper` and `packages/test-helpers`
- Added `@vaultkeeper/test-helpers` package providing `InMemoryBackend` and `TestVault` for fast, hermetic tests
- Shared TypeScript config via `tsconfig.base.json`, shared ESLint config at workspace root
- Added vitest workspace configuration for cross-package test execution
- Added changesets for version and changelog management
