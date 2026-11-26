import { describe, it, expect, afterEach } from 'vitest'
import { currentPlatform, isDarwin, isWindows, isLinux } from '../../../src/util/platform.js'
import { SetupError } from '../../../src/errors.js'

describe('currentPlatform', () => {
  it('returns the current platform without throwing', () => {
    // The test runner is on a supported platform; this must not throw.
    const platform = currentPlatform()
    expect(['darwin', 'win32', 'linux']).toContain(platform)
  })

  it('returns a value consistent with process.platform', () => {
    const platform = currentPlatform()
    expect(platform).toBe(process.platform)
  })

  // Regression: issue #127 — an unsupported process.platform previously threw
  // a plain `Error`, breaking instanceof-based handling. It must now throw a
  // typed SetupError.
  describe('on an unsupported platform', () => {
    const original = Object.getOwnPropertyDescriptor(process, 'platform')

    afterEach(() => {
      if (original !== undefined) {
        Object.defineProperty(process, 'platform', original)
      }
    })

    it('throws a typed SetupError naming the platform dependency', () => {
      Object.defineProperty(process, 'platform', { value: 'freebsd', configurable: true })

      try {
        currentPlatform()
        expect.unreachable('currentPlatform should have thrown for an unsupported platform')
      } catch (err) {
        if (!(err instanceof SetupError)) {
          throw err
        }
        expect(err.dependency).toBe('platform')
        expect(err.message).toContain('freebsd')
      }
    })
  })
})

describe('isDarwin', () => {
  it('returns a boolean', () => {
    expect(typeof isDarwin()).toBe('boolean')
  })

  it('returns true only on darwin', () => {
    expect(isDarwin()).toBe(process.platform === 'darwin')
  })
})

describe('isWindows', () => {
  it('returns a boolean', () => {
    expect(typeof isWindows()).toBe('boolean')
  })

  it('returns true only on win32', () => {
    expect(isWindows()).toBe(process.platform === 'win32')
  })
})

describe('isLinux', () => {
  it('returns a boolean', () => {
    expect(typeof isLinux()).toBe('boolean')
  })

  it('returns true only on linux', () => {
    expect(isLinux()).toBe(process.platform === 'linux')
  })
})

describe('platform helpers are mutually exclusive', () => {
  it('at most one of isDarwin/isWindows/isLinux returns true', () => {
    const trueCount = [isDarwin(), isWindows(), isLinux()].filter(Boolean).length
    // On supported platforms exactly one is true; on others none are true.
    expect(trueCount).toBeLessThanOrEqual(1)
  })
})
