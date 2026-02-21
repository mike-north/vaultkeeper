import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest'
import { KeyManager } from '../../../src/keys/manager.js'
import { RotationInProgressError, SetupError } from '../../../src/errors.js'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeManager(): KeyManager {
  return new KeyManager()
}

async function makeInitializedManager(): Promise<KeyManager> {
  const mgr = makeManager()
  await mgr.init()
  return mgr
}

// ---------------------------------------------------------------------------
// generateKey
// ---------------------------------------------------------------------------

describe('KeyManager.generateKey', () => {
  it('produces a 32-byte key', async () => {
    const mgr = await makeInitializedManager()
    const key = mgr.generateKey()
    expect(key.key).toBeInstanceOf(Uint8Array)
    expect(key.key.byteLength).toBe(32)
  })

  it('generates a unique id with k- prefix', async () => {
    const mgr = await makeInitializedManager()
    const key = mgr.generateKey()
    expect(key.id).toMatch(/^k-\d+-[0-9a-f]+$/)
  })

  it('sets createdAt to approximately now', async () => {
    const before = Date.now()
    const mgr = await makeInitializedManager()
    const key = mgr.generateKey()
    const after = Date.now()
    expect(key.createdAt.getTime()).toBeGreaterThanOrEqual(before)
    expect(key.createdAt.getTime()).toBeLessThanOrEqual(after)
  })

  it('generates distinct keys on successive calls', async () => {
    const mgr = await makeInitializedManager()
    const a = mgr.generateKey()
    const b = mgr.generateKey()
    // Keys should not share the same raw bytes (astronomically unlikely).
    expect(Buffer.from(a.key).toString('hex')).not.toBe(
      Buffer.from(b.key).toString('hex'),
    )
  })
})

// ---------------------------------------------------------------------------
// init
// ---------------------------------------------------------------------------

describe('KeyManager.init', () => {
  it('makes getCurrentKey available', async () => {
    const mgr = await makeInitializedManager()
    expect(mgr.getCurrentKey()).toBeDefined()
  })

  it('sets no previous key on first init', async () => {
    const mgr = await makeInitializedManager()
    expect(mgr.getPreviousKey()).toBeUndefined()
  })

  it('is idempotent — calling init() twice keeps the same current key', async () => {
    const mgr = await makeInitializedManager()
    const first = mgr.getCurrentKey()
    await mgr.init()
    expect(mgr.getCurrentKey().id).toBe(first.id)
  })
})

// ---------------------------------------------------------------------------
// getCurrentKey / getPreviousKey before init
// ---------------------------------------------------------------------------

describe('KeyManager before init', () => {
  it('getCurrentKey throws SetupError if not initialized', () => {
    const mgr = makeManager()
    expect(() => mgr.getCurrentKey()).toThrow(SetupError)
    expect(() => mgr.getCurrentKey()).toThrow('KeyManager has not been initialized')
  })

  it('getPreviousKey throws SetupError if not initialized', () => {
    const mgr = makeManager()
    expect(() => mgr.getPreviousKey()).toThrow(SetupError)
    expect(() => mgr.getPreviousKey()).toThrow('KeyManager has not been initialized')
  })

  it('findKeyById throws SetupError if not initialized', () => {
    const mgr = makeManager()
    expect(() => mgr.findKeyById('k-123')).toThrow(SetupError)
    expect(() => mgr.findKeyById('k-123')).toThrow('KeyManager has not been initialized')
  })

  it('rotateKey throws SetupError if not initialized', () => {
    const mgr = makeManager()
    expect(() => { mgr.rotateKey(1000) }).toThrow(SetupError)
    expect(() => { mgr.rotateKey(1000) }).toThrow('KeyManager has not been initialized')
  })
})

// ---------------------------------------------------------------------------
// rotateKey — basic lifecycle
// ---------------------------------------------------------------------------

describe('KeyManager.rotateKey — lifecycle', () => {
  it('replaces the current key with a new one', async () => {
    const mgr = await makeInitializedManager()
    const before = mgr.getCurrentKey()
    mgr.rotateKey(60_000)
    const after = mgr.getCurrentKey()
    expect(after.id).not.toBe(before.id)
  })

  it('promotes old current to previous during grace period', async () => {
    const mgr = await makeInitializedManager()
    const original = mgr.getCurrentKey()
    mgr.rotateKey(60_000)
    const previous = mgr.getPreviousKey()
    expect(previous).toBeDefined()
    expect(previous?.id).toBe(original.id)
  })

  it('isInGracePeriod returns true immediately after rotation', async () => {
    const mgr = await makeInitializedManager()
    mgr.rotateKey(60_000)
    expect(mgr.isInGracePeriod()).toBe(true)
  })

  it('isInGracePeriod returns false before any rotation', async () => {
    const mgr = await makeInitializedManager()
    expect(mgr.isInGracePeriod()).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// rotateKey — grace period expiry (using fake timers)
// ---------------------------------------------------------------------------

describe('KeyManager.rotateKey — grace period timing', () => {
  beforeEach(() => {
    vi.useFakeTimers()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it('clears previous key when grace period elapses', async () => {
    const mgr = await makeInitializedManager()
    mgr.rotateKey(5_000)
    expect(mgr.getPreviousKey()).toBeDefined()

    vi.advanceTimersByTime(5_001)

    expect(mgr.getPreviousKey()).toBeUndefined()
  })

  it('isInGracePeriod returns false after grace period elapses', async () => {
    const mgr = await makeInitializedManager()
    mgr.rotateKey(3_000)
    expect(mgr.isInGracePeriod()).toBe(true)

    vi.advanceTimersByTime(3_001)

    expect(mgr.isInGracePeriod()).toBe(false)
  })

  it('isInGracePeriod returns true while time has not elapsed', async () => {
    const mgr = await makeInitializedManager()
    mgr.rotateKey(10_000)

    vi.advanceTimersByTime(9_999)

    expect(mgr.isInGracePeriod()).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// rotateKey — concurrent rotation guard
// ---------------------------------------------------------------------------

describe('KeyManager.rotateKey — concurrent rotation guard', () => {
  beforeEach(() => {
    vi.useFakeTimers()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it('throws RotationInProgressError when a rotation is already active', async () => {
    const mgr = await makeInitializedManager()
    mgr.rotateKey(5_000)

    expect(() => { mgr.rotateKey(5_000) }).toThrowError(RotationInProgressError)
  })

  it('allows a new rotation after the grace period expires', async () => {
    const mgr = await makeInitializedManager()
    mgr.rotateKey(1_000)

    vi.advanceTimersByTime(1_001)

    expect(() => { mgr.rotateKey(1_000) }).not.toThrow()
  })
})

// ---------------------------------------------------------------------------
// revokeKey
// ---------------------------------------------------------------------------

describe('KeyManager.revokeKey', () => {
  beforeEach(() => {
    vi.useFakeTimers()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it('replaces the current key', async () => {
    const mgr = await makeInitializedManager()
    const before = mgr.getCurrentKey()
    mgr.revokeKey()
    expect(mgr.getCurrentKey().id).not.toBe(before.id)
  })

  it('immediately clears the previous key', async () => {
    const mgr = await makeInitializedManager()
    mgr.rotateKey(60_000)
    expect(mgr.getPreviousKey()).toBeDefined()

    mgr.revokeKey()

    expect(mgr.getPreviousKey()).toBeUndefined()
  })

  it('ends any in-progress grace period', async () => {
    const mgr = await makeInitializedManager()
    mgr.rotateKey(60_000)
    expect(mgr.isInGracePeriod()).toBe(true)

    mgr.revokeKey()

    expect(mgr.isInGracePeriod()).toBe(false)
  })

  it('allows a subsequent rotation after revocation', async () => {
    const mgr = await makeInitializedManager()
    mgr.rotateKey(1_000)
    mgr.revokeKey()

    expect(() => { mgr.rotateKey(1_000) }).not.toThrow()
  })

  it('can be called without a prior rotation', async () => {
    const mgr = await makeInitializedManager()
    expect(() => { mgr.revokeKey() }).not.toThrow()
    expect(mgr.getPreviousKey()).toBeUndefined()
  })
})

// ---------------------------------------------------------------------------
// findKeyById
// ---------------------------------------------------------------------------

describe('KeyManager.findKeyById', () => {
  it('finds the current key by id', async () => {
    const mgr = await makeInitializedManager()
    const current = mgr.getCurrentKey()
    expect(mgr.findKeyById(current.id)).toBeDefined()
    expect(mgr.findKeyById(current.id)?.id).toBe(current.id)
  })

  it('finds the previous key by id during grace period', async () => {
    const mgr = await makeInitializedManager()
    const original = mgr.getCurrentKey()
    mgr.rotateKey(60_000)
    expect(mgr.findKeyById(original.id)?.id).toBe(original.id)
  })

  it('returns undefined for an unknown id', async () => {
    const mgr = await makeInitializedManager()
    expect(mgr.findKeyById('k-does-not-exist')).toBeUndefined()
  })

  it('returns undefined for empty string id', async () => {
    const mgr = await makeInitializedManager()
    expect(mgr.findKeyById('')).toBeUndefined()
  })
})

describe('KeyManager.findKeyById — grace period expiry', () => {
  beforeEach(() => {
    vi.useFakeTimers()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it('returns undefined for the previous key after grace period elapses', async () => {
    const mgr = await makeInitializedManager()
    const original = mgr.getCurrentKey()
    mgr.rotateKey(2_000)

    vi.advanceTimersByTime(2_001)

    expect(mgr.findKeyById(original.id)).toBeUndefined()
  })
})
