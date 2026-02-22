import { describe, it, expect } from 'vitest'
import { formatError } from '../../src/output.js'

describe('formatError', () => {
  it('should format Error instances with name and message', () => {
    const err = new Error('something broke')
    expect(formatError(err)).toBe('Error: something broke')
  })

  it('should format custom error classes', () => {
    class CustomError extends Error {
      constructor(message: string) {
        super(message)
        this.name = 'CustomError'
      }
    }
    expect(formatError(new CustomError('bad'))).toBe('CustomError: bad')
  })

  it('should stringify non-Error values', () => {
    expect(formatError('string error')).toBe('string error')
    expect(formatError(42)).toBe('42')
    expect(formatError(null)).toBe('null')
  })
})
