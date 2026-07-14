---
'vaultkeeper': patch
---

Fix the published `.d.ts` failing to typecheck in strict consumer projects that scope `compilerOptions.types` explicitly (`TS2591: Cannot find name 'Buffer'`). `SecretAccessor.read()`, `SignRequest.data`, and `VerifyRequest.data` now resolve `Buffer` via a real `node:buffer` import plus a `/// <reference types="node" />` directive in the published rollup, instead of relying on the ambient global. `@types/node` is now declared as an optional peer dependency.
