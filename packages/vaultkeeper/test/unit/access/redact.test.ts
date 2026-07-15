import { describe, it, expect } from 'vitest'
import { redactSecrets, REDACTED } from '../../../src/access/redact.js'

describe('redactSecrets', () => {
  it('replaces every occurrence of a single secret with [REDACTED]', () => {
    expect(redactSecrets('token=sk_live_abc and again sk_live_abc', ['sk_live_abc'])).toBe(
      `token=${REDACTED} and again ${REDACTED}`,
    )
  })

  it('redacts every value when multiple secrets are given', () => {
    const text = 'api=key123 db=pass456 mixed key123/pass456'
    expect(redactSecrets(text, ['key123', 'pass456'])).toBe(
      `api=${REDACTED} db=${REDACTED} mixed ${REDACTED}/${REDACTED}`,
    )
  })

  it('leaves text unchanged when no secret is present', () => {
    expect(redactSecrets('nothing to hide here', ['absent'])).toBe('nothing to hide here')
  })

  it('skips empty secret values (an empty string must not blank the text)', () => {
    // An empty string matches between every character; redacting it would
    // destroy the output. It must be treated as a no-op.
    expect(redactSecrets('hello world', [''])).toBe('hello world')
    expect(redactSecrets('a real real one', ['', 'real'])).toBe(`a ${REDACTED} ${REDACTED} one`)
  })

  it('skips whitespace-only secret values (must not blank ubiquitous whitespace)', () => {
    // A whitespace-only secret would match the spaces throughout the text and
    // shred it. It must be dropped like an empty string.
    expect(redactSecrets('a b c d', ['   '])).toBe('a b c d')
    expect(redactSecrets('tab\tsep', ['\t'])).toBe('tab\tsep')
  })

  // Regression (PR #195 review): when one secret is a prefix/substring of
  // another, redacting the shorter first leaves the longer secret's suffix
  // visible (e.g. "abc" before "abc123" -> "[REDACTED]123", leaking "123").
  // Redaction must sort longer-first so the longer value is fully masked, and
  // the outcome must not depend on the order the secrets are supplied in.
  it('fully redacts a longer secret even when a shorter one is its prefix (no suffix leak)', () => {
    const shortFirst = redactSecrets('key=abc123', ['abc', 'abc123'])
    const longFirst = redactSecrets('key=abc123', ['abc123', 'abc'])

    for (const result of [shortFirst, longFirst]) {
      expect(result).not.toContain('abc123')
      expect(result).not.toContain('123')
      expect(result).toBe(`key=${REDACTED}`)
    }
    // Order-independent.
    expect(shortFirst).toBe(longFirst)
  })

  it('redacts both a shared-prefix secret and its standalone shorter sibling', () => {
    // The shorter secret also appears on its own elsewhere; both the standalone
    // occurrence and the longer superstring must be masked, leaking neither raw
    // value nor the longer secret's suffix.
    const result = redactSecrets('a=abc b=abc123', ['abc', 'abc123'])
    expect(result).not.toContain('abc')
    expect(result).not.toContain('123')
    expect(result).toBe(`a=${REDACTED} b=${REDACTED}`)
  })

  it('uses a custom replacement token when provided', () => {
    expect(redactSecrets('my secret value', ['secret'], '***')).toBe('my *** value')
  })

  it('returns text unchanged for an empty secrets list', () => {
    expect(redactSecrets('untouched', [])).toBe('untouched')
  })

  it('exposes REDACTED as the default token', () => {
    expect(REDACTED).toBe('[REDACTED]')
  })

  // Regression guards for the literal-matching contract (PR #195 review).
  // replaceAll with a string pattern is spec-literal today, but redactSecrets
  // is a public shared API — a future refactor to RegExp-based replacement
  // would silently reintroduce metacharacter interpretation.
  it('matches secrets containing regex metacharacters literally', () => {
    const secret = 'a.b*c$1(x)[y]+?'
    expect(redactSecrets(`token=${secret};`, [secret])).toBe(`token=${REDACTED};`)
    // A near-miss that a regex interpretation of '.' or '*' would match:
    expect(redactSecrets('token=aXbbbc11xxyy;', [secret])).toBe('token=aXbbbc11xxyy;')
  })

  // '$&' in a replacement string re-expands to the matched substring — i.e.
  // the secret itself. The replacement must be inserted verbatim so a custom
  // token can never accidentally preserve what it was meant to erase.
  it('inserts the replacement literally — $-substitution patterns cannot re-expand the secret', () => {
    expect(redactSecrets('key=hunter2', ['hunter2'], '<$&>')).toBe('key=<$&>')
    expect(redactSecrets('key=hunter2', ['hunter2'], '$$ paid')).toBe('key=$$ paid')
    expect(redactSecrets('key=hunter2', ['hunter2'], "$'")).toBe("key=$'")
  })
})
