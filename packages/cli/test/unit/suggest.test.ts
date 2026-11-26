/**
 * Unit tests for the unknown-command suggestion helper (issue #216, item 5).
 *
 * `suggestCommand` powers the npm/git/cargo-style "did you mean …?" hint on an
 * unknown subcommand. It must confidently correct near-miss typos while never
 * offering a misleading suggestion for a genuinely unrelated word.
 */
import { describe, it, expect } from 'vitest'
import { levenshtein, suggestCommand, KNOWN_COMMANDS } from '../../src/suggest.js'

describe('levenshtein', () => {
  it('is 0 for identical strings', () => {
    expect(levenshtein('doctor', 'doctor')).toBe(0)
  })

  it('equals the other length when one string is empty', () => {
    expect(levenshtein('', 'doctor')).toBe(6)
    expect(levenshtein('exec', '')).toBe(4)
  })

  it('counts a single substitution as distance 1', () => {
    expect(levenshtein('doctor', 'doctdr')).toBe(1)
  })

  it('counts a transposition (doctro → doctor) as 2 substitutions', () => {
    // Levenshtein has no transposition primitive, so a swapped pair costs 2.
    expect(levenshtein('doctro', 'doctor')).toBe(2)
  })
})

describe('suggestCommand', () => {
  it('suggests the closest command for a near-miss typo', () => {
    expect(suggestCommand('doctro')).toBe('doctor')
    expect(suggestCommand('docter')).toBe('doctor')
    expect(suggestCommand('exce')).toBe('exec')
    expect(suggestCommand('stroe')).toBe('store')
    expect(suggestCommand('verfy')).toBe('verify')
  })

  it('suggests a command missing/adding a single character', () => {
    expect(suggestCommand('confi')).toBe('config')
    expect(suggestCommand('configg')).toBe('config')
  })

  it('returns undefined for an empty input', () => {
    expect(suggestCommand('')).toBeUndefined()
  })

  it('returns undefined for a wildly unrelated word (no misleading guess)', () => {
    expect(suggestCommand('xyz')).toBeUndefined()
    expect(suggestCommand('frobnicate')).toBeUndefined()
    expect(suggestCommand('deploy')).toBeUndefined()
  })

  it('returns the exact command (distance 0) when the input is already valid', () => {
    for (const command of KNOWN_COMMANDS) {
      expect(suggestCommand(command)).toBe(command)
    }
  })

  it('honors an explicit command list', () => {
    expect(suggestCommand('bild', ['build', 'test'])).toBe('build')
    expect(suggestCommand('zzzz', ['build', 'test'])).toBeUndefined()
  })
})
