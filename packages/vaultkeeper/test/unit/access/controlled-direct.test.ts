import { describe, it, expect } from 'vitest'
import { createSecretAccessor } from '../../../src/access/controlled-direct.js'
import type { SecretAccessor } from '../../../src/types.js'

// Symbol used by Node.js for custom inspect
const INSPECT_CUSTOM = Symbol.for('nodejs.util.inspect.custom')

/** Safely get a property via Reflect to avoid unbound-method linting issues. */
function getProperty(obj: SecretAccessor, key: string | symbol): unknown {
  return Reflect.get(obj, key)
}

describe('createSecretAccessor', () => {
  describe('read() basic behavior', () => {
    it('calls the callback with a Buffer containing the secret', () => {
      const accessor = createSecretAccessor('my-secret')
      let received: Buffer | undefined

      accessor.read((buf) => {
        received = Buffer.from(buf) // copy before zeroing
      })

      expect(received).toBeDefined()
      expect(received?.toString('utf8')).toBe('my-secret')
    })

    it('zeros the buffer after callback returns', () => {
      const accessor = createSecretAccessor('abc')
      let capturedBuf: Buffer | undefined

      accessor.read((buf) => {
        capturedBuf = buf // retain reference, don't copy
      })

      // After read() returns, the buffer should be zeroed
      expect(capturedBuf).toBeDefined()
      expect(capturedBuf?.every((b) => b === 0)).toBe(true)
    })

    it('zeros the buffer even if callback throws', () => {
      const accessor = createSecretAccessor('secret')
      let capturedBuf: Buffer | undefined

      expect(() => {
        accessor.read((buf) => {
          capturedBuf = buf
          throw new Error('callback error')
        })
      }).toThrow('callback error')

      expect(capturedBuf?.every((b) => b === 0)).toBe(true)
    })
  })

  describe('double-read prevention', () => {
    it('throws a descriptive domain error (not TypeError) on second call to read()', () => {
      const accessor = createSecretAccessor('secret')

      accessor.read(() => {
        // first call: ok
      })

      // The consumed flag blocks re-execution with a descriptive domain error.
      // Asserting on the message ensures this is NOT a raw Proxy revocation
      // TypeError (which would also pass a bare `.toThrow(Error)` check).
      expect(() => {
        accessor.read(() => {
          // should never reach here
        })
      }).toThrow('already been consumed')
    })

    it('second read() error is not a TypeError (no raw proxy error)', () => {
      const accessor = createSecretAccessor('secret')

      accessor.read(() => {
        // consume
      })

      let caught: unknown
      try {
        accessor.read(() => {
          // unreachable
        })
      } catch (err) {
        caught = err
      }

      expect(caught).toBeInstanceOf(Error)
      expect(caught).not.toBeInstanceOf(TypeError)
    })

    it('accessor is still accessible via property get after read() is called', () => {
      const accessor = createSecretAccessor('secret')

      accessor.read(() => {
        // consume
      })

      // Property access must work (no revocation) — only calling read() again is blocked
      expect(typeof getProperty(accessor, 'read')).toBe('function')
    })

    it('accessor remains usable after await if read() has not been called', async () => {
      const accessor = createSecretAccessor('secret')

      // Await a microtask — accessor must still be usable because read() was not called.
      await Promise.resolve()

      let called = false
      expect(() => {
        accessor.read(() => {
          called = true
        })
      }).not.toThrow()
      expect(called).toBe(true)
    })
  })

  describe('custom inspect', () => {
    it('returns [SecretAccessor] from the custom inspect symbol', () => {
      const accessor = createSecretAccessor('secret')

      const inspectFn = getProperty(accessor, INSPECT_CUSTOM)
      expect(typeof inspectFn).toBe('function')
      if (typeof inspectFn === 'function') {
        // inspectFn is narrowed to Function but we can't call it without unsafe-call.
        // Use Reflect.apply to safely invoke with no args.
        const result: unknown = Reflect.apply(inspectFn, accessor, [])
        expect(result).toBe('[SecretAccessor]')
      }
    })
  })

  describe('proxy trap behaviors', () => {
    it('set trap: cannot overwrite read property', () => {
      const accessor = createSecretAccessor('secret')

      // Reflect.set returns false when the trap returns false
      const result = Reflect.set(accessor, 'read', () => undefined)
      expect(result).toBe(false)

      // The read property still works
      expect(typeof getProperty(accessor, 'read')).toBe('function')
    })

    it('has trap: returns true for "read" key', () => {
      const accessor = createSecretAccessor('secret')
      expect('read' in accessor).toBe(true)
    })

    it('has trap: returns false for unknown keys', () => {
      const accessor = createSecretAccessor('secret')
      expect('unknownKey' in accessor).toBe(false)
    })

    it('deleteProperty trap: cannot delete read', () => {
      const accessor = createSecretAccessor('secret')

      // Reflect.deleteProperty returns false when the trap returns false
      const deleted = Reflect.deleteProperty(accessor, 'read')
      expect(deleted).toBe(false)

      // read should still work
      expect(typeof getProperty(accessor, 'read')).toBe('function')
    })

    it('getPrototypeOf trap: returns null', () => {
      const accessor = createSecretAccessor('secret')
      const proto: unknown = Object.getPrototypeOf(accessor)
      expect(proto).toBeNull()
    })

    it('isExtensible trap: returns false', () => {
      const accessor = createSecretAccessor('secret')
      expect(Object.isExtensible(accessor)).toBe(false)
    })

    it('preventExtensions trap: returns true (already not extensible)', () => {
      const accessor = createSecretAccessor('secret')
      expect(() => Object.preventExtensions(accessor)).not.toThrow()
    })

    it('ownKeys trap: includes "read"', () => {
      const accessor = createSecretAccessor('secret')
      expect(Reflect.ownKeys(accessor)).toContain('read')
    })

    it('getOwnPropertyDescriptor trap: returns descriptor for "read"', () => {
      const accessor = createSecretAccessor('secret')
      const desc = Object.getOwnPropertyDescriptor(accessor, 'read')
      expect(desc).toBeDefined()
      expect(desc?.configurable).toBe(true)
      expect(desc?.enumerable).toBe(true)
    })

    it('getOwnPropertyDescriptor trap: returns undefined for unknown key', () => {
      const accessor = createSecretAccessor('secret')
      const desc = Object.getOwnPropertyDescriptor(accessor, 'unknownKey')
      expect(desc).toBeUndefined()
    })

    it('defineProperty trap: returns false', () => {
      const accessor = createSecretAccessor('secret')
      const result = Reflect.defineProperty(accessor, 'newProp', { value: 42 })
      expect(result).toBe(false)
    })

    it('setPrototypeOf trap: returns false', () => {
      const accessor = createSecretAccessor('secret')
      const result = Reflect.setPrototypeOf(accessor, {})
      expect(result).toBe(false)
    })
  })

  describe('proxy remains accessible after read() is consumed', () => {
    /** Helper: create an accessor and consume it via read(). */
    function makeConsumedAccessor(): SecretAccessor {
      const accessor = createSecretAccessor('s')
      accessor.read(() => {
        // consume
      })
      return accessor
    }

    it('get trap still works after read() is consumed', () => {
      const accessor = makeConsumedAccessor()
      expect(() => getProperty(accessor, 'read')).not.toThrow()
    })

    it('has trap still works after read() is consumed', () => {
      const accessor = makeConsumedAccessor()
      expect(() => 'read' in accessor).not.toThrow()
    })

    it('ownKeys trap still works after read() is consumed', () => {
      const accessor = makeConsumedAccessor()
      expect(() => Reflect.ownKeys(accessor)).not.toThrow()
    })

    it('getPrototypeOf trap still works after read() is consumed', () => {
      const accessor = makeConsumedAccessor()
      expect(() => {
        const _proto: unknown = Object.getPrototypeOf(accessor)
        return _proto
      }).not.toThrow()
    })

    it('isExtensible trap still works after read() is consumed', () => {
      const accessor = makeConsumedAccessor()
      expect(() => Object.isExtensible(accessor)).not.toThrow()
    })

    it('getOwnPropertyDescriptor trap still works after read() is consumed', () => {
      const accessor = makeConsumedAccessor()
      expect(() => Object.getOwnPropertyDescriptor(accessor, 'read')).not.toThrow()
    })
  })
})
