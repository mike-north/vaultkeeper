---
"vaultkeeper": major
---

Reduce public API surface from ~80 to ~33 symbols. Internal implementation details (JWE plumbing, KeyManager, doctor checks, identity/trust helpers, access helpers, config helpers, backend classes) are no longer exported. All internalized symbols are marked `@internal` and remain accessible via deep imports for cross-package use.
