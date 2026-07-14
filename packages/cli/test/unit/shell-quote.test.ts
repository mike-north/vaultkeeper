import { describe, it, expect } from 'vitest'
import { shellQuote } from '../../src/shell-quote.js'

describe('shellQuote', () => {
  it('wraps a plain path in single quotes', () => {
    expect(shellQuote('/usr/local/bin/tool')).toBe("'/usr/local/bin/tool'")
  })

  it('preserves spaces inside the quotes', () => {
    expect(shellQuote('/path/with spaces/tool')).toBe("'/path/with spaces/tool'")
  })

  it('quotes shell metacharacters literally (no expansion)', () => {
    // $, ;, &, |, and backticks must be inert when the result is pasted.
    expect(shellQuote('/tmp/$(rm -rf ~)/x')).toBe("'/tmp/$(rm -rf ~)/x'")
    expect(shellQuote('/tmp/a;b&c|d')).toBe("'/tmp/a;b&c|d'")
    expect(shellQuote('/tmp/`whoami`')).toBe("'/tmp/`whoami`'")
  })

  it('escapes embedded single quotes as \\047 close/escape/reopen', () => {
    // a'b -> 'a'\''b'
    expect(shellQuote("a'b")).toBe("'a'\\''b'")
  })

  it('handles multiple single quotes', () => {
    expect(shellQuote("'x'")).toBe("''\\''x'\\'''")
  })

  it('quotes an empty string as a pair of single quotes', () => {
    expect(shellQuote('')).toBe("''")
  })
})
