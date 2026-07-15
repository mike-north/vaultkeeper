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

  it('uses a custom replacement token when provided', () => {
    expect(redactSecrets('my secret value', ['secret'], '***')).toBe('my *** value')
  })

  it('returns text unchanged for an empty secrets list', () => {
    expect(redactSecrets('untouched', [])).toBe('untouched')
  })

  it('exposes REDACTED as the default token', () => {
    expect(REDACTED).toBe('[REDACTED]')
  })
})
