---
'vaultkeeper': minor
'@vaultkeeper/cli': minor
'@vaultkeeper/cli-test-helpers': minor
---

Add a global `--config-dir <path>` flag / `VAULTKEEPER_CONFIG_DIR` environment variable to the CLI so every command (`store`, `delete`, `exec`, `approve`, `dev-mode`, `doctor`, `config`, `rotate-key`, `revoke-key`) can be pointed at an isolated config directory — the flag wins over the env var, which wins over the platform default. `config init` creates the override directory as needed, and `config show` reports the path it loaded from. The library's `getDefaultConfigDir()` and `loadConfig()` are now public so embedders and the CLI share the same resolution logic. `@vaultkeeper/cli-test-helpers`'s `createCliTestEnv()` gains a `configDirMode` option (`'env'` | `'flag'`) and no longer manipulates the subprocess's `HOME` directory to achieve isolation.
