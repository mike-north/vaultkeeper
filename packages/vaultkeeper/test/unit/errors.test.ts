import { describe, it, expect } from 'vitest'
import {
  FilesystemError,
  toFilesystemError,
  UnreachableError,
  VaultError,
} from '../../src/errors.js'

/** Build a Node.js-shaped filesystem error with a `code` (e.g. 'ENOENT'). */
function fsError(code: string, message: string): NodeJS.ErrnoException {
  return Object.assign(new Error(message), { code })
}

// ---------------------------------------------------------------------------
// Regression: issue #133 — #126 wrapped fs failures in FilesystemError but
// discarded the underlying NodeJS.ErrnoException, so `.code` survived only as
// text inside `.message` and `.cause` was never set. Consumers had to
// string-match the message to distinguish e.g. EACCES from ENOSPC.
// ---------------------------------------------------------------------------

describe('FilesystemError', () => {
  it('should populate code and cause from an EACCES errno cause (permission failure)', () => {
    const cause = fsError('EACCES', 'permission denied')
    const err = new FilesystemError('Failed to read file at /x', '/x', 'read', cause)

    expect(err.code).toBe('EACCES')
    expect(err.cause).toBe(cause)
  })

  it('should populate code and cause from an ENOSPC errno cause (non-permission failure)', () => {
    const cause = fsError('ENOSPC', 'no space left on device')
    const err = new FilesystemError('Failed to write file at /x', '/x', 'write', cause)

    expect(err.code).toBe('ENOSPC')
    expect(err.cause).toBe(cause)
  })

  it('should leave code undefined when constructed without a cause', () => {
    const err = new FilesystemError('Failed to read file at /x', '/x', 'read')

    expect(err.code).toBeUndefined()
    expect(err.cause).toBeUndefined()
  })

  it('should leave code undefined when the cause has no string code', () => {
    const cause = new Error('something went wrong')
    const err = new FilesystemError('Failed to read file at /x', '/x', 'read', cause)

    expect(err.code).toBeUndefined()
    // cause is still preserved even without a usable errno code
    expect(err.cause).toBe(cause)
  })

  it('should leave code undefined when the cause is not an Error', () => {
    const err = new FilesystemError('Failed to read file at /x', '/x', 'read', 'not an error')

    expect(err.code).toBeUndefined()
    expect(err.cause).toBe('not an error')
  })

  // Regression: issue #133 review — a plain `this.cause = cause` assignment
  // makes `cause` an enumerable own property, unlike the standard
  // `new Error(message, { cause })` form, which installs it as
  // non-enumerable. That mismatch would make `cause` show up in
  // `Object.keys()`/`JSON.stringify()` output where a native cause would not.
  it('should record cause as a non-enumerable own property, matching native Error.cause', () => {
    const cause = fsError('EACCES', 'permission denied')
    const err = new FilesystemError('Failed to read file at /x', '/x', 'read', cause)

    expect(Object.prototype.hasOwnProperty.call(err, 'cause')).toBe(true)
    const descriptor = Object.getOwnPropertyDescriptor(err, 'cause')
    expect(descriptor?.enumerable).toBe(false)
    expect(descriptor?.writable).toBe(true)
    expect(descriptor?.configurable).toBe(true)
    // Own enumerable properties (path/permission/code) are unaffected.
    expect(Object.keys(err)).toEqual(expect.arrayContaining(['path', 'permission', 'code']))
    expect(Object.keys(err)).not.toContain('cause')
  })
})

describe('toFilesystemError', () => {
  it('should build a FilesystemError describing the resource, path, and operation, preserving code and cause', () => {
    const cause = fsError('EACCES', 'permission denied')
    const err = toFilesystemError(cause, 'secret file', '/entries/a.enc', 'write')

    expect(err).toBeInstanceOf(FilesystemError)
    expect(err.message).toBe('Failed to write secret file at /entries/a.enc: permission denied')
    expect(err.path).toBe('/entries/a.enc')
    expect(err.permission).toBe('write')
    expect(err.code).toBe('EACCES')
    expect(err.cause).toBe(cause)
  })

  it('should describe a non-Error cause via String() and still leave code undefined', () => {
    const err = toFilesystemError('boom', 'wrapping key file', '/x/.key', 'read')

    expect(err.message).toBe('Failed to read wrapping key file at /x/.key: boom')
    expect(err.code).toBeUndefined()
    expect(err.cause).toBe('boom')
  })
})

// ---------------------------------------------------------------------------
// UnreachableError (issue #340) — the exhaustiveness-check error. The type
// system only guarantees the compile-time contract (see
// test/types/unreachable-error.test-d.ts); these are the runtime-shape
// assertions (VaultError subclass, name, message, and the `.describedValue`
// diagnostic field) that criterion 1 also requires.
//
// The repo forbids `as` casts, so a value that has genuinely bypassed
// exhaustive narrowing (the only real way to reach `UnreachableError` at
// runtime — e.g. an unvalidated payload from outside the type system) is
// simulated with a deliberately-lying type predicate, matching the
// `Record<string, unknown>`-narrowing pattern already used for the same
// purpose in test/unit/jwe/claims.test.ts.
// ---------------------------------------------------------------------------

/** Always returns true; only used to narrow a test value to `never`. */
function isNever(_value: unknown): _value is never {
  return true
}

/** Narrows any test-time value to `never`, without an `as` cast. */
function toNeverForTest(value: unknown): never {
  if (isNever(value)) {
    return value
  }
  throw new Error('unreachable: isNever always returns true')
}

describe('UnreachableError', () => {
  it('should extend VaultError and set its own name', () => {
    const err = new UnreachableError(toNeverForTest('unexpected'))

    expect(err).toBeInstanceOf(VaultError)
    expect(err).toBeInstanceOf(Error)
    expect(err.name).toBe('UnreachableError')
  })

  it('should embed the unexpected value in the message', () => {
    const err = new UnreachableError(toNeverForTest('unexpected'))

    expect(err.message).toContain('"unexpected"')
    expect(err.describedValue).toBe('"unexpected"')
  })

  it('should embed an optional detail string in the message', () => {
    const err = new UnreachableError(toNeverForTest('bogus'), 'unrecognized claim kind')

    expect(err.message).toBe(
      'Reached unreachable code (unrecognized claim kind): unexpected value "bogus"',
    )
  })

  it('should describe undefined and null distinctly from other values', () => {
    expect(new UnreachableError(toNeverForTest(undefined)).describedValue).toBe('undefined')
    expect(new UnreachableError(toNeverForTest(null)).describedValue).toBe('null')
  })

  it('should describe a non-string primitive via JSON.stringify', () => {
    const err = new UnreachableError(toNeverForTest(42))

    expect(err.describedValue).toBe('42')
  })

  // -------------------------------------------------------------------------
  // Regression: describeUnreachableValue must never throw and must always
  // produce a non-empty, informative string, even for inputs where
  // `JSON.stringify` returns `undefined` (despite its TypeScript signature
  // claiming `string`) or throws outright. This is the diagnostic path for a
  // value that has already defeated static exhaustiveness checking, so it
  // must not itself fail when handed a hostile runtime value.
  // -------------------------------------------------------------------------

  it('should describe a function without throwing', () => {
    function namedFn(): void {
      // no-op
    }

    const err = new UnreachableError(toNeverForTest(namedFn))

    expect(err.describedValue).toBe('[Function: namedFn]')
    expect(err.describedValue.length).toBeGreaterThan(0)
  })

  it('should describe an anonymous function without throwing', () => {
    const anonymous = (): void => {
      // no-op
    }
    // Strip the name JS infers from the `const` binding so the fallback
    // branch (empty function name) is actually exercised.
    Object.defineProperty(anonymous, 'name', { value: '' })

    const err = new UnreachableError(toNeverForTest(anonymous))

    expect(err.describedValue).toBe('[Function: anonymous]')
  })

  it('should describe a symbol without throwing', () => {
    const err = new UnreachableError(toNeverForTest(Symbol('bogus-kind')))

    expect(err.describedValue).toBe('Symbol(bogus-kind)')
  })

  it('should describe a BigInt without throwing', () => {
    // Built from a string, not a numeric literal, so the value exceeds
    // Number.MAX_SAFE_INTEGER without losing precision beforehand.
    const err = new UnreachableError(toNeverForTest(BigInt('9007199254740993')))

    expect(err.describedValue).toBe('9007199254740993n')
  })

  it('should describe an object whose toJSON returns undefined without a literal "undefined" body', () => {
    // JSON.stringify({ toJSON: () => undefined }) runs to completion without
    // throwing but returns the *value* `undefined` (not the string
    // "undefined") — its TypeScript signature claims `string` regardless.
    // The message must still be non-empty and must not silently collapse to
    // the same rendering as the real `undefined` value.
    const toJsonUndefined = { toJSON: (): undefined => undefined }

    const err = new UnreachableError(toNeverForTest(toJsonUndefined))

    expect(err.describedValue.length).toBeGreaterThan(0)
    expect(err.describedValue).toBe('[object Object]')
  })

  it('should describe a circular object without throwing', () => {
    const circular: Record<string, unknown> = { name: 'circular' }
    circular.self = circular

    const err = new UnreachableError(toNeverForTest(circular))

    expect(err.describedValue).toBe('[object Object]')
  })

  it('should describe an object with a throwing getter without throwing', () => {
    const hostile: Record<string, unknown> = {}
    Object.defineProperty(hostile, 'poison', {
      enumerable: true,
      get(): never {
        throw new Error('getter boom')
      },
    })

    const err = new UnreachableError(toNeverForTest(hostile))

    expect(err.describedValue).toBe('[object Object]')
  })

  it('should describe an object with a throwing Symbol.toStringTag getter without throwing', () => {
    // JSON.stringify never reads Symbol.toStringTag, so it must be made to
    // throw for an unrelated reason (a circular reference) first, forcing
    // fallthrough to Object.prototype.toString — which is what actually
    // reads Symbol.toStringTag and is the thing this test exercises.
    const hostile: Record<PropertyKey, unknown> = {}
    hostile.self = hostile
    Object.defineProperty(hostile, Symbol.toStringTag, {
      get(): never {
        throw new Error('toStringTag boom')
      },
    })

    const err = new UnreachableError(toNeverForTest(hostile))

    expect(err.describedValue).toBe('[unstringifiable value]')
  })

  it('should describe an Error instance by its name and message, not "{}"', () => {
    // `Error#message`/`name` are non-enumerable, so JSON.stringify alone
    // would render any Error instance as the uninformative '{}'.
    const err = new UnreachableError(toNeverForTest(new TypeError('bad kind')))

    expect(err.describedValue).toBe('[Error TypeError: bad kind]')
  })

  it('should fall through safely for an Error subclass with a throwing message getter', () => {
    class HostileMessageError extends Error {
      constructor() {
        super()
        Object.defineProperty(this, 'message', {
          get(): never {
            throw new Error('message boom')
          },
        })
      }
    }

    const err = new UnreachableError(toNeverForTest(new HostileMessageError()))

    // The throwing getter forces a fall-through past the Error-specific
    // branch to the JSON.stringify fallback, which renders an Error
    // instance's (non-enumerable, so invisible to it) message as '{}'.
    expect(err.describedValue).toBe('{}')
  })
})
