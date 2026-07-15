import { describe, it, expect } from 'vitest'
import * as fs from 'node:fs'
import * as path from 'node:path'
import { fileURLToPath } from 'node:url'

/**
 * Repo-wide guard: CLAUDE.md states "Never throw plain `Error` objects —
 * always use a typed subclass from the error hierarchy." Issue #115 first
 * enforced this for `config.ts` alone; issue #127 audited the rest of the
 * package and broadened the guard to every source file, so a future edit
 * anywhere under `src/` that reintroduces a plain `Error` construction fails
 * CI instead of silently regressing the convention.
 *
 * Matches three ways a plain `Error` can escape:
 *   - `throw new Error(...)` / `throw Error(...)` (no `new`) /
 *     `throw new globalThis.Error(...)`
 *   - `reject(new Error(...))` inside a `new Promise((resolve, reject) => ...)`
 *     executor — functionally the same escape as a `throw`, since the
 *     rejection is what a consumer observes
 *   - `Promise.reject(new Error(...))`
 *
 * This is a source-text scan, not a type-level check, so it is inherently a
 * best-effort net (e.g. it would not catch a plain Error constructed once
 * and referenced by variable before being thrown/rejected several lines
 * later) — but it catches every pattern actually used in this codebase.
 */
const PLAIN_ERROR_PATTERN =
  /(?:throw\s+|reject\(\s*|Promise\.reject\(\s*)(?:new\s+)?(?:globalThis\.)?Error\s*\(/

const SRC_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../src')

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

describe('plain-Error audit (issue #127)', () => {
  const sourceFiles = collectSourceFiles(SRC_DIR)

  it('finds source files to scan', () => {
    expect(sourceFiles.length).toBeGreaterThan(0)
  })

  it.each(sourceFiles.map((f) => [path.relative(SRC_DIR, f), f] as const))(
    'contains no plain-Error throw/reject in %s',
    (_relPath, filePath) => {
      const source = fs.readFileSync(filePath, 'utf8')
      expect(source).not.toMatch(PLAIN_ERROR_PATTERN)
    },
  )

  describe('PLAIN_ERROR_PATTERN (negative control)', () => {
    it('matches a bare throw', () => {
      expect('throw new Error("x")').toMatch(PLAIN_ERROR_PATTERN)
    })

    it('matches throw without new', () => {
      expect('throw Error("x")').toMatch(PLAIN_ERROR_PATTERN)
    })

    it('matches throw new globalThis.Error', () => {
      expect('throw new globalThis.Error("x")').toMatch(PLAIN_ERROR_PATTERN)
    })

    it('matches reject(new Error(...))', () => {
      expect('reject(new Error("x"))').toMatch(PLAIN_ERROR_PATTERN)
    })

    it('matches Promise.reject(new Error(...))', () => {
      expect('Promise.reject(new Error("x"))').toMatch(PLAIN_ERROR_PATTERN)
    })

    it('does not match a typed VaultError subclass being thrown', () => {
      expect('throw new SecretNotFoundError("x")').not.toMatch(PLAIN_ERROR_PATTERN)
    })

    it('does not match a typed VaultError subclass being rejected', () => {
      expect('reject(new BackendUnavailableError("x", "y", []))').not.toMatch(PLAIN_ERROR_PATTERN)
    })

    it('does not match a class declaration extending Error', () => {
      expect('export class ConfigDirFlagError extends Error {}').not.toMatch(PLAIN_ERROR_PATTERN)
    })

    it('does not match a comment mentioning `new Error(`', () => {
      expect('// Matches the native `new Error(message, { cause })` form').not.toMatch(
        PLAIN_ERROR_PATTERN,
      )
    })
  })
})
