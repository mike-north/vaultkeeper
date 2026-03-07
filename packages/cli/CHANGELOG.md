# @vaultkeeper/cli

## 0.1.5

### Patch Changes

- [#35](https://github.com/mike-north/vaultkeeper/pull/35) [`5a907e1`](https://github.com/mike-north/vaultkeeper/commit/5a907e138ba336dc7da140170950c93b1c7f43ee) Thanks [@mike-north](https://github.com/mike-north)! - Patch release to verify end-to-end publishing pipeline after release infrastructure fixes (crates.io gating, workspace dependency version sync, cross-platform compatibility)

## 0.1.4

### Patch Changes

- [#20](https://github.com/mike-north/vaultkeeper/pull/20) [`c65c107`](https://github.com/mike-north/vaultkeeper/commit/c65c1076802dcc5e2710c47fd60e3f1771858fe1) Thanks [@mike-north](https://github.com/mike-north)! - Add VAULTKEEPER_CONFIG_DIR env var for test isolation and introduce @vaultkeeper/cli-test-helpers package with reusable CLI test infrastructure

- Updated dependencies [[`c65c107`](https://github.com/mike-north/vaultkeeper/commit/c65c1076802dcc5e2710c47fd60e3f1771858fe1), [`3f95e3b`](https://github.com/mike-north/vaultkeeper/commit/3f95e3b954cb6f046e34f2155da9ff945d47c16e)]:
  - vaultkeeper@1.0.1

## 0.1.3

### Patch Changes

- Updated dependencies [[`5353518`](https://github.com/mike-north/vaultkeeper/commit/535351866ef9cb4e77edb9b2b757911e74b3b402), [`c0d36c5`](https://github.com/mike-north/vaultkeeper/commit/c0d36c5f5bdc7848574863514bfe53e23ce83d42)]:
  - vaultkeeper@1.0.0

## 0.1.2

### Patch Changes

- Updated dependencies [[`a1d2e57`](https://github.com/mike-north/vaultkeeper/commit/a1d2e57fe3b2132d63755c31acc332b90ae7a799)]:
  - vaultkeeper@0.4.0

## 0.1.1

### Patch Changes

- Updated dependencies [[`a000092`](https://github.com/mike-north/vaultkeeper/commit/a000092848e94e130893d145d07a8b8bf6fc1ead), [`c2c4e8c`](https://github.com/mike-north/vaultkeeper/commit/c2c4e8cfd94e624b4ad7dfd2f3b22a6046d91c8e), [`7398ff6`](https://github.com/mike-north/vaultkeeper/commit/7398ff6352b8d3e39e562ace50b8caa8ef998882)]:
  - vaultkeeper@0.3.0

## 0.1.0

### Minor Changes

- [#8](https://github.com/mike-north/vaultkeeper/pull/8) [`e9fc9bb`](https://github.com/mike-north/vaultkeeper/commit/e9fc9bb060cd6b6cf510fb0e6b1a9076eab00088) Thanks [@mike-north](https://github.com/mike-north)! - Add `@vaultkeeper/cli` package — command-line interface for vaultkeeper secret management. Provides `vaultkeeper exec` for injecting secrets as environment variables with output redaction, plus commands for doctor checks, secret storage, key rotation, and configuration management.

### Patch Changes

- Updated dependencies [[`1f1412c`](https://github.com/mike-north/vaultkeeper/commit/1f1412c7b76c7810b395df4b9de44ebe21a16188)]:
  - vaultkeeper@0.2.0
