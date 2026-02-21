/**
 * Controlled direct access pattern.
 *
 * Provides a `SecretAccessor` backed by a revocable Proxy that:
 * - Exposes a single `.read()` method
 * - Passes a Buffer containing the secret to the callback
 * - Zeros the buffer after the callback returns
 * - Prevents double-read (throws on second call)
 * - Revokes the proxy synchronously after the first `read()` call completes
 * - Redacts itself from Node.js inspect output
 */

import type { SecretAccessor } from '../types.js'

const INSPECT_CUSTOM = Symbol.for('nodejs.util.inspect.custom')

/** Extended accessor that also supports custom inspect. */
interface SecretAccessorInternal extends SecretAccessor {
  [INSPECT_CUSTOM](): string
}

/**
 * Proxy target class that satisfies SecretAccessorInternal.
 *
 * Instances have their prototype set to null and are made non-extensible
 * after construction, so all proxy invariants can be met consistently:
 * - getPrototypeOf trap returns null (matches actual prototype)
 * - isExtensible trap returns false (matches actual extensibility)
 * - ownKeys trap includes all own keys (matches non-extensible contract)
 */
class SecretAccessorTarget implements SecretAccessorInternal {
  readonly read: (callback: (buf: Buffer) => void) => void
  readonly [INSPECT_CUSTOM]: () => string

  constructor(
    readImpl: (callback: (buf: Buffer) => void) => void,
    inspectImpl: () => string,
  ) {
    this.read = readImpl
    this[INSPECT_CUSTOM] = inspectImpl
  }
}

/**
 * Create a `SecretAccessor` for the given secret value.
 *
 * The accessor is backed by a revocable Proxy with all 13 traps implemented.
 * The proxy is revoked synchronously after the first `read()` call completes
 * (in the `finally` block, after zeroing the buffer). Any subsequent property
 * access will throw a TypeError.
 *
 * This avoids the `queueMicrotask(revoke)` approach which breaks async callers
 * that `await` between receiving the accessor and calling `.read()`.
 */
export function createSecretAccessor(secretValue: string): SecretAccessor {
  let consumed = false
  // Holder allows readImpl to close over the revoke function without a let/reassignment.
  const revokeHolder: { fn: (() => void) | undefined } = { fn: undefined }

  // Close over the actual read logic.
  function readImpl(callback: (buf: Buffer) => void): void {
    if (consumed) {
      throw new Error('SecretAccessor has already been consumed — call getSecret() again to obtain a new accessor')
    }
    consumed = true

    const buf = Buffer.from(secretValue, 'utf8')
    try {
      callback(buf)
    } finally {
      buf.fill(0)
      // Revoke the proxy synchronously so no further property access is possible.
      revokeHolder.fn?.()
    }
  }

  function inspectImpl(): string {
    return '[SecretAccessor]'
  }

  // Build the proxy target: a class instance with null prototype and
  // non-extensible to satisfy V8's proxy invariants for those traps.
  const target = new SecretAccessorTarget(readImpl, inspectImpl)
  Object.setPrototypeOf(target, null)
  Object.preventExtensions(target)

  // All 13 proxy handler traps.
  const handler: Required<ProxyHandler<SecretAccessorInternal>> = {
    get(_t, prop, _receiver) {
      if (prop === 'read') return readImpl
      if (prop === INSPECT_CUSTOM) return inspectImpl
      return undefined
    },
    set(_t, _prop, _value, _receiver) {
      return false
    },
    has(_t, prop) {
      return prop === 'read' || prop === INSPECT_CUSTOM
    },
    deleteProperty(_t, _prop) {
      return false
    },
    apply(_t, _thisArg, _args) {
      throw new TypeError('SecretAccessor is not a function')
    },
    construct(_t, _args, _newTarget) {
      throw new TypeError('SecretAccessor is not a constructor')
    },
    defineProperty(_t, _prop, _descriptor) {
      return false
    },
    getOwnPropertyDescriptor(_t, prop) {
      if (prop === 'read') {
        return { configurable: true, enumerable: true, writable: false, value: readImpl }
      }
      if (prop === INSPECT_CUSTOM) {
        return { configurable: true, enumerable: false, writable: false, value: inspectImpl }
      }
      return undefined
    },
    getPrototypeOf(_t) {
      // Null prototype — matches the actual target prototype after setPrototypeOf(target, null).
      return null
    },
    setPrototypeOf(_t, _proto) {
      return false
    },
    isExtensible(_t) {
      // Non-extensible — matches the actual target extensibility.
      return false
    },
    preventExtensions(_t) {
      // Already non-extensible — trap returns true (success) matching target state.
      return true
    },
    ownKeys(_t) {
      // Must include all own keys of the non-extensible target.
      // The target has 'read' and INSPECT_CUSTOM as own properties.
      return ['read', INSPECT_CUSTOM]
    },
  }

  const { proxy, revoke } = Proxy.revocable(target, handler)
  // Wire up the revoke function so readImpl can call it after the callback returns.
  revokeHolder.fn = revoke

  return proxy
}
