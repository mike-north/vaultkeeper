import { describe, it, expect } from 'vitest'
import * as fs from 'node:fs'
import * as path from 'node:path'
import { fileURLToPath } from 'node:url'

/**
 * Guards against a library-package regression: a runtime error message or
 * public JSDoc comment instructing the user to run a bare `vaultkeeper
 * config init` as if the CLI shipped with this package. `vaultkeeper` has no
 * `bin` — the CLI ships separately as `@vaultkeeper/cli` — so every mention
 * of `vaultkeeper config init` must be qualified with `@vaultkeeper/cli`
 * (or a JS-API alternative) in the surrounding text (issue #100).
 */

const SRC_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../src')

const BARE_COMMAND_PATTERN = /vaultkeeper config init/g

/** Recursively collect every `.ts` file under `dir`. */
function collectSourceFiles(dir: string): string[] {
  const entries = fs.readdirSync(dir, { withFileTypes: true })
  const files: string[] = []
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name)
    if (entry.isDirectory()) {
      files.push(...collectSourceFiles(fullPath))
    } else if (entry.isFile() && entry.name.endsWith('.ts') && !entry.name.endsWith('.test.ts')) {
      files.push(fullPath)
    }
  }
  return files
}

/**
 * Split file content into blocks separated by blank lines. JSDoc comments
 * and multi-line string-concatenation statements are each contiguous
 * non-blank runs, so this keeps a qualification on an adjacent line in the
 * same block as the bare command it qualifies.
 */
function splitIntoBlocks(content: string): string[] {
  return content.split(/\n\s*\n/)
}

describe('library must not reference a bare CLI command (issue #100)', () => {
  const sourceFiles = collectSourceFiles(SRC_DIR)

  it('finds source files to scan', () => {
    expect(sourceFiles.length).toBeGreaterThan(0)
  })

  it.each(sourceFiles.map((f) => [path.relative(SRC_DIR, f), f] as const))(
    'qualifies every "vaultkeeper config init" mention in %s',
    (_relPath, filePath) => {
      const content = fs.readFileSync(filePath, 'utf-8')
      const blocks = splitIntoBlocks(content)

      for (const block of blocks) {
        const matches = block.match(BARE_COMMAND_PATTERN)
        if (matches === null) {
          continue
        }
        expect(
          block.includes('@vaultkeeper/cli'),
          `"vaultkeeper config init" in ${path.relative(SRC_DIR, filePath)} must be qualified ` +
            'with "@vaultkeeper/cli" (or a JS-API alternative) in the same comment/statement block:\n\n' +
            block,
        ).toBe(true)
      }
    },
  )

  it('rejects an unqualified bare command (negative control)', () => {
    const block = "Run 'vaultkeeper config init' to create a valid config."
    expect(block.includes('@vaultkeeper/cli')).toBe(false)
  })
})
