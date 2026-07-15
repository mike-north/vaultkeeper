---
"@vaultkeeper/test-helpers": patch
---

Loosen the `vaultkeeper` peerDependency range from `workspace:^` (published as `^0.6.0`) to an explicit `>=0.6.0 <1`. The caret range was minor-locked under 0.x, so a routine `vaultkeeper` minor bump (e.g. 0.6.0 → 0.7.0) would exit the range and trigger a changesets-driven major bump on `@vaultkeeper/test-helpers` — silently graduating it to 1.0.0 with no changeset declaring that intent. The new range tracks the pre-1.0 vaultkeeper line explicitly and only forces a major on `@vaultkeeper/test-helpers` once `vaultkeeper` itself reaches 1.0.0, which is the point such a cascade should actually happen.

This also requires enabling changesets' `onlyUpdatePeerDependentsWhenOutOfRange` option (see `.changeset/config.json`): by default, changesets bumps a package major on *any* non-patch release of a peer dependency, regardless of whether the new version still satisfies the declared peer range. Without that option, the widened range alone would not have stopped the cascade.
