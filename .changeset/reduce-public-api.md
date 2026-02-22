---
"vaultkeeper": minor
---

Reduce public API surface from ~80 to ~33 symbols. Internal implementation details (JWE plumbing, KeyManager, doctor checks, identity/trust helpers, access helpers, config helpers, backend classes) are no longer exported from the package entrypoint. All internalized symbols are marked `@internal`; while they may still be reachable via deep imports in workspace/monorepo builds, they are not part of the published package's supported public API.
