/**
 * Tests for ListableBackend interface and isListableBackend type guard.
 */

import { describe, it, expect } from 'vitest'
import { isListableBackend } from '../../../src/backend/types.js'
import type { SecretBackend } from '../../../src/backend/types.js'

function createMockBackend(overrides: Partial<SecretBackend> = {}): SecretBackend {
  return {
    type: 'mock',
    displayName: 'Mock',
    isAvailable: () => Promise.resolve(true),
    store: () => Promise.resolve(),
    retrieve: () => Promise.resolve('secret'),
    delete: () => Promise.resolve(),
    exists: () => Promise.resolve(true),
    ...overrides,
  }
}

describe('isListableBackend', () => {
  it('should return true for a backend with a list method', () => {
    const backend = {
      ...createMockBackend(),
      list: () => Promise.resolve([]),
    }
    expect(isListableBackend(backend)).toBe(true)
  })

  it('should return false for a backend without a list method', () => {
    const backend = createMockBackend()
    expect(isListableBackend(backend)).toBe(false)
  })

  it('should return false when list is not a function', () => {
    const backend = createMockBackend()
    // Attach a non-function `list` property
    Object.defineProperty(backend, 'list', { value: 'not-a-function', enumerable: true })
    expect(isListableBackend(backend)).toBe(false)
  })

  it('should narrow the type so list() can be called', () => {
    const backend: SecretBackend = {
      ...createMockBackend(),
      list: () => Promise.resolve(['a', 'b']),
    }
    if (isListableBackend(backend)) {
      // TypeScript should allow this without errors
      const result: Promise<string[]> = backend.list()
      expect(result).toBeInstanceOf(Promise)
    } else {
      // Force test failure if guard returns false incorrectly
      expect.unreachable('Expected isListableBackend to return true')
    }
  })
})
