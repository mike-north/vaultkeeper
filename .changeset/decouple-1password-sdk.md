---
'vaultkeeper': minor
---

Make `@1password/sdk` an optional peer dependency instead of a runtime dependency. Installing `vaultkeeper` no longer pulls `@1password/sdk` (and its `@1password/sdk-core` transitive) into the dependency closure — the file-backend path stays `jose`-only. The 1Password backend now loads the SDK lazily (via dynamic `import()`) only when that backend is actually used, and fails with a typed `PluginNotFoundError` naming the missing `@1password/sdk` peer when it is not installed. To use the 1Password backend, install `@1password/sdk` alongside `vaultkeeper`.
