#!/usr/bin/env node
/**
 * Prepends `/// <reference types="node" />` to the built declaration
 * rollups.
 *
 * The published `.d.ts`/`.d.cts` reference `Buffer`. tsup's declaration
 * bundler (rollup-plugin-dts) already turns the source's
 * `import type { Buffer } from 'node:buffer'` into a real import in the
 * rollup, which resolves for consumers whose tsconfig auto-includes
 * `@types/node` (the common case).
 *
 * Consumers who scope `compilerOptions.types` explicitly (e.g. `types: []`,
 * common in strict monorepo boilerplates) do not auto-include
 * `@types/node`'s ambient module declarations — which also back its
 * `node:buffer` module shim — so even the real import fails to resolve
 * there. This reference directive forces `@types/node` into the consumer's
 * program regardless of their `types` scoping. It has to be reinjected here
 * because rollup-plugin-dts strips triple-slash directives from source
 * during bundling.
 *
 * @see https://github.com/mike-north/vaultkeeper/issues/72
 */

import { readFile, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const REFERENCE_DIRECTIVE = '/// <reference types="node" />\n'

const packageRoot = join(dirname(fileURLToPath(import.meta.url)), '..')
const distFiles = ['dist/index.d.ts', 'dist/index.d.cts'].map((relative) =>
  join(packageRoot, relative),
)

for (const distFile of distFiles) {
  const contents = await readFile(distFile, 'utf8')
  if (contents.startsWith(REFERENCE_DIRECTIVE)) continue
  await writeFile(distFile, REFERENCE_DIRECTIVE + contents)
}
