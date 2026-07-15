---
'vaultkeeper': patch
---

Replace the guessed "TypeScript 5.x" README note with the actually-tested range: a CI matrix (`packages/vaultkeeper/test/e2e/consumer-typecheck.test.ts`) now typechecks the shipped `.d.ts` of `vaultkeeper`, `@vaultkeeper/test-helpers`, and `@vaultkeeper/cli-test-helpers` against pinned TypeScript 5.0.4, 5.9.3, 6.0.3, and 7.0.2 compilers — all pass, so both READMEs now state a tested 5.0.4–7.0.2 range instead of a narrower guess.
