import { describe, it, expect, afterEach } from 'vitest'
import { bold, dim } from '../../src/output.js'

describe('bold', () => {
  afterEach(() => {
    Object.defineProperty(process.stdout, 'isTTY', { value: undefined, configurable: true })
  })

  it('should return plain text when stdout is not a TTY', () => {
    Object.defineProperty(process.stdout, 'isTTY', { value: false, configurable: true })
    expect(bold('hello')).toBe('hello')
  })

  it('should return plain text when stdout.isTTY is undefined', () => {
    Object.defineProperty(process.stdout, 'isTTY', { value: undefined, configurable: true })
    expect(bold('world')).toBe('world')
  })

  it('should wrap in ANSI bold when stdout is a TTY', () => {
    Object.defineProperty(process.stdout, 'isTTY', { value: true, configurable: true })
    expect(bold('hello')).toBe('\x1b[1mhello\x1b[22m')
  })

  it('should handle an empty string', () => {
    Object.defineProperty(process.stdout, 'isTTY', { value: true, configurable: true })
    expect(bold('')).toBe('\x1b[1m\x1b[22m')
  })
})

describe('dim', () => {
  afterEach(() => {
    Object.defineProperty(process.stdout, 'isTTY', { value: undefined, configurable: true })
  })

  it('should return plain text when stdout is not a TTY', () => {
    Object.defineProperty(process.stdout, 'isTTY', { value: false, configurable: true })
    expect(dim('hello')).toBe('hello')
  })

  it('should return plain text when stdout.isTTY is undefined', () => {
    Object.defineProperty(process.stdout, 'isTTY', { value: undefined, configurable: true })
    expect(dim('world')).toBe('world')
  })

  it('should wrap in ANSI dim when stdout is a TTY', () => {
    Object.defineProperty(process.stdout, 'isTTY', { value: true, configurable: true })
    expect(dim('hello')).toBe('\x1b[2mhello\x1b[22m')
  })

  it('should handle an empty string', () => {
    Object.defineProperty(process.stdout, 'isTTY', { value: true, configurable: true })
    expect(dim('')).toBe('\x1b[2m\x1b[22m')
  })
})
