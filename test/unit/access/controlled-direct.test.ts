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
    it('throws on second call to read() because the proxy is revoked after the first read', () => {
      const accessor = createSecretAccessor('secret')

      accessor.read(() => {
        // first call: ok
      })

      // After read() completes the proxy is revoked synchronously, so any
      // subsequent property access (including calling .read again) throws TypeError.
      expect(() => {
        accessor.read(() => {
          // should never reach here
        })
      }).toThrow(TypeError)
    })
  })

  describe('synchronous revocation after read()', () => {
    it('accessor is usable before read() is called', () => {
      const accessor = createSecretAccessor('secret')

      // Still accessible before any read
      expect(() => {
        accessor.read(() => {
          // fine
        })
      }).not.toThrow()
    })

    it('revokes the proxy synchronously after read() returns', () => {
      const accessor = createSecretAccessor('secret')

      accessor.read(() => {
        // first call succeeds
      })

      // Proxy is revoked synchronously — any property access now throws TypeError.
      expect(() => {
        // Any property access on a revoked proxy throws TypeError
        accessor.read(() => {
          // unreachable
        })
      }).toThrow(TypeError)
    })

    it('throws TypeError for property get access after read()', () => {
      const accessor = createSecretAccessor('secret')
      accessor.read(() => {
        // consume
      })
      expect(() => getProperty(accessor, 'read')).toThrow(TypeError)
    })

    it('accessor remains usable after await if read() has not been called', async () => {
      // Regression test: queueMicrotask(revoke) would have broken this.
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

  describe('all property access throws TypeError after revocation', () => {
    /** Helper: create an accessor and consume it so the proxy is revoked. */
    function makeConsumedAccessor(): SecretAccessor {
      const accessor = createSecretAccessor('s')
      accessor.read(() => {
        // consume — triggers synchronous revocation in finally block
      })
      return accessor
    }

    it('get trap throws after revocation', () => {
      const accessor = makeConsumedAccessor()
      expect(() => getProperty(accessor, 'read')).toThrow(TypeError)
    })

    it('has trap throws after revocation', () => {
      const accessor = makeConsumedAccessor()
      expect(() => 'read' in accessor).toThrow(TypeError)
    })

    it('ownKeys trap throws after revocation', () => {
      const accessor = makeConsumedAccessor()
      expect(() => Reflect.ownKeys(accessor)).toThrow(TypeError)
    })

    it('getPrototypeOf trap throws after revocation', () => {
      const accessor = makeConsumedAccessor()
      expect(() => {
        const _proto: unknown = Object.getPrototypeOf(accessor)
        return _proto
      }).toThrow(TypeError)
    })

    it('isExtensible trap throws after revocation', () => {
      const accessor = makeConsumedAccessor()
      expect(() => Object.isExtensible(accessor)).toThrow(TypeError)
    })

    it('getOwnPropertyDescriptor trap throws after revocation', () => {
      const accessor = makeConsumedAccessor()
      expect(() => Object.getOwnPropertyDescriptor(accessor, 'read')).toThrow(TypeError)
    })

    it('set trap throws after revocation', () => {
      const accessor = makeConsumedAccessor()
      expect(() => Reflect.set(accessor, 'x', 1)).toThrow(TypeError)
    })

    it('deleteProperty trap throws after revocation', () => {
      const accessor = makeConsumedAccessor()
      expect(() => Reflect.deleteProperty(accessor, 'read')).toThrow(TypeError)
    })

    it('defineProperty trap throws after revocation', () => {
      const accessor = makeConsumedAccessor()
      expect(() => Reflect.defineProperty(accessor, 'x', {})).toThrow(TypeError)
    })

    it('setPrototypeOf trap throws after revocation', () => {
      const accessor = makeConsumedAccessor()
      expect(() => Reflect.setPrototypeOf(accessor, null)).toThrow(TypeError)
    })
  })
})
