import { describe, it, expect } from 'vitest'
import { FilesystemError, toFilesystemError } from '../../src/errors.js'

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
