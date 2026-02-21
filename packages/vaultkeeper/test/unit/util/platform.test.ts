import { describe, it, expect } from 'vitest'
import { currentPlatform, isDarwin, isWindows, isLinux } from '../../../src/util/platform.js'

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
