import { describe, it, expect } from 'vitest'
import {
  resolvePlaceholders,
  resolvePlaceholdersInRecord,
  PLACEHOLDER,
  ANY_PLACEHOLDER_RE,
} from '../../../src/access/placeholder.js'
import { VaultError } from '../../../src/errors.js'

describe('resolvePlaceholders', () => {
  describe('single-secret mode (string)', () => {
    it('replaces {{secret}} with the secret value', () => {
      expect(resolvePlaceholders('Bearer {{secret}}', 'tok123')).toBe(
        'Bearer tok123',
      )
    })

    it('replaces multiple occurrences', () => {
      expect(resolvePlaceholders('{{secret}}-{{secret}}', 'x')).toBe('x-x')
    })

    it('returns the original string when no placeholder is present', () => {
      expect(resolvePlaceholders('no placeholder', 'secret')).toBe(
        'no placeholder',
      )
    })

    it('leaves {{secret:name}} placeholders unreplaced', () => {
      expect(resolvePlaceholders('{{secret:apiKey}}', 'val')).toBe(
        '{{secret:apiKey}}',
      )
    })
  })

  describe('named-secret mode (Record)', () => {
    it('replaces {{secret:name}} with the corresponding value', () => {
      const secrets = { apiKey: 'key123', dbPass: 'pass456' }
      expect(
        resolvePlaceholders('key={{secret:apiKey}} pass={{secret:dbPass}}', secrets),
      ).toBe('key=key123 pass=pass456')
    })

    it('replaces multiple occurrences of the same name', () => {
      const secrets = { tok: 'abc' }
      expect(
        resolvePlaceholders('{{secret:tok}}-{{secret:tok}}', secrets),
      ).toBe('abc-abc')
    })

    it('returns the original string when no named placeholder is present', () => {
      const secrets = { tok: 'abc' }
      expect(resolvePlaceholders('no placeholder', secrets)).toBe(
        'no placeholder',
      )
    })

    it('leaves {{secret}} unreplaced in named mode', () => {
      const secrets = { tok: 'abc' }
      expect(resolvePlaceholders('{{secret}}', secrets)).toBe('{{secret}}')
    })

    it('throws VaultError for unknown secret name', () => {
      const secrets = { apiKey: 'key123' }
      expect(() =>
        resolvePlaceholders('{{secret:unknown}}', secrets),
      ).toThrow(VaultError)
      expect(() =>
        resolvePlaceholders('{{secret:unknown}}', secrets),
      ).toThrow(/Unknown secret name.*unknown/)
    })

    it('includes available names in error message', () => {
      const secrets = { apiKey: 'key', dbPass: 'pass' }
      expect(() =>
        resolvePlaceholders('{{secret:missing}}', secrets),
      ).toThrow(/apiKey, dbPass/)
    })
  })
})

describe('resolvePlaceholdersInRecord', () => {
  it('replaces placeholders in all values (single-secret)', () => {
    const record = { AUTH: 'Bearer {{secret}}', PLAIN: 'static' }
    const result = resolvePlaceholdersInRecord(record, 'tok')
    expect(result).toEqual({ AUTH: 'Bearer tok', PLAIN: 'static' })
  })

  it('replaces named placeholders in all values', () => {
    const record = { A: '{{secret:x}}', B: '{{secret:y}}' }
    const result = resolvePlaceholdersInRecord(record, { x: '1', y: '2' })
    expect(result).toEqual({ A: '1', B: '2' })
  })

  it('does not mutate the original record', () => {
    const record = { KEY: '{{secret}}' }
    resolvePlaceholdersInRecord(record, 'val')
    expect(record.KEY).toBe('{{secret}}')
  })
})

describe('PLACEHOLDER constant', () => {
  it('is the literal {{secret}} string', () => {
    expect(PLACEHOLDER).toBe('{{secret}}')
  })
})

describe('ANY_PLACEHOLDER_RE', () => {
  it('matches {{secret}}', () => {
    expect(ANY_PLACEHOLDER_RE.test('{{secret}}')).toBe(true)
  })

  it('matches {{secret:name}}', () => {
    expect(ANY_PLACEHOLDER_RE.test('{{secret:apiKey}}')).toBe(true)
  })

  it('does not match plain text', () => {
    expect(ANY_PLACEHOLDER_RE.test('no placeholder')).toBe(false)
  })
})
