#!/usr/bin/env node
// Functional fingerprint for a wasm-bindgen-produced .wasm module, used as the
// wasm-guards CI job's drift check (issue #240).
//
// Why not a plain byte hash: a pinned Rust/wasm-pack/wasm-opt toolchain does
// NOT produce byte-identical output across different host platforms (e.g. the
// macOS build that produced a committed artifact vs. CI's Linux rebuild), even
// given byte-identical source. Confirmed by diffing an actual CI-produced
// rebuild against a local macOS rebuild of the same commit: internal type-table
// slot assignment, data-segment string ordering, and the indirect-call table
// all differ, plus wasm-bindgen's per-build closure-shim disambiguator hashes
// (e.g. `wasm_bindgen__closure__destroy__h<16 hex>`) differ — wasm-bindgen's
// proc-macro always compiles for and runs on the host, not the wasm32 target,
// so this hash is host-platform-dependent, not a function of the Rust source.
// None of this reflects an actual behavior difference: the accompanying JS/TS
// glue is always regenerated as a matched pair referencing whatever names the
// wasm module actually exports.
//
// This script instead fingerprints the module's actual contract: the set of
// exports and imports (name + kind), with the known-volatile closure-shim
// hash suffix normalized away, sorted so table/section ordering differences
// don't matter. Two modules with an identical fingerprint expose the same
// public surface; a real API change (added/removed/renamed export, changed
// import) always changes it — verified locally by removing a real export and
// confirming the fingerprint check flags the mismatch.
//
// Usage:
//   node wasm-export-fingerprint.mjs <a.wasm> <b.wasm>   # compare, exit 1 on mismatch
//   node wasm-export-fingerprint.mjs <a.wasm>            # print a.wasm's fingerprint

import { readFileSync } from 'node:fs'

const HASH_SUFFIX = /__h[0-9a-f]{16}$/

function normalizeName(name) {
  return name.replace(HASH_SUFFIX, '__hNORMALIZED')
}

function byName(a, b) {
  return a.name < b.name ? -1 : a.name > b.name ? 1 : 0
}

function fingerprint(path) {
  const mod = new WebAssembly.Module(readFileSync(path))

  const exports = WebAssembly.Module.exports(mod)
    .map((e) => ({ name: normalizeName(e.name), kind: e.kind }))
    .sort(byName)

  const imports = WebAssembly.Module.imports(mod)
    .map((i) => ({ module: i.module, name: normalizeName(i.name), kind: i.kind }))
    .sort(byName)

  return { exportCount: exports.length, importCount: imports.length, exports, imports }
}

function main() {
  const [pathA, pathB] = process.argv.slice(2)
  if (!pathA) {
    console.error('usage: wasm-export-fingerprint.mjs <a.wasm> [b.wasm]')
    process.exit(2)
  }

  const a = fingerprint(pathA)
  if (!pathB) {
    console.log(JSON.stringify(a, null, 2))
    return
  }

  const b = fingerprint(pathB)
  const same = JSON.stringify(a) === JSON.stringify(b)

  console.log(`export count: ${a.exportCount} vs ${b.exportCount}`)
  console.log(`import count: ${a.importCount} vs ${b.importCount}`)

  if (same) {
    console.log('fingerprints match')
    return
  }

  console.error('fingerprint mismatch:')
  const maxExports = Math.max(a.exports.length, b.exports.length)
  for (let i = 0; i < maxExports; i++) {
    const ea = JSON.stringify(a.exports[i] ?? null)
    const eb = JSON.stringify(b.exports[i] ?? null)
    if (ea !== eb) console.error(`  export[${i}]: ${ea} vs ${eb}`)
  }
  const maxImports = Math.max(a.imports.length, b.imports.length)
  for (let i = 0; i < maxImports; i++) {
    const ia = JSON.stringify(a.imports[i] ?? null)
    const ib = JSON.stringify(b.imports[i] ?? null)
    if (ia !== ib) console.error(`  import[${i}]: ${ia} vs ${ib}`)
  }
  process.exit(1)
}

main()
