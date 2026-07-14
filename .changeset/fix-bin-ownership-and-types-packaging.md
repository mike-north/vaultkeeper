---
"vaultkeeper": patch
"@vaultkeeper/test-helpers": patch
"@vaultkeeper/cli-test-helpers": patch
---

Remove the top-level `package.json#types` field, which pointed at an API Extractor rollup (`dist/<name>-public.d.ts`) that the release pipeline never generates before `changeset publish` and was therefore absent from the published tarball. Types now resolve entirely through the conditional `exports` map, which already pointed at the real per-format `tsup` output. `@vaultkeeper/cli-test-helpers`'s `exports` conditions, which had the same stale rollup reference, now point at the real `dist/index.d.ts` / `dist/index.d.cts` files as well.

Confirms (and now enforces via a packaging test) that only `@vaultkeeper/cli` declares the `vaultkeeper` bin — the `vaultkeeper` library package was already free of a `bin` field in this repo, but the registry had previously observed contradictory bin ownership across published versions.
