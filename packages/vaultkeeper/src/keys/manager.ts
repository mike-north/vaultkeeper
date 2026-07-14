/**
 * Key management for vaultkeeper, including generation, rotation, revocation,
 * and grace-period tracking.
 */

import * as crypto from 'node:crypto'
import { RotationInProgressError, SetupError } from '../errors.js'
import type { KeyMaterial, KeyState, KeyStateSnapshot } from './types.js'

/**
 * Manage cryptographic keys with rotation and grace-period semantics.
 *
 * @remarks
 * Whether a rotation is "in progress" is derived entirely from
 * {@link KeyManager.isInGracePeriod} — a grace period is active exactly while a
 * previous key is still usable. This makes the state serializable via
 * {@link KeyManager.snapshot}/{@link KeyManager.hydrate}, so the guard against a
 * second rotation survives a process restart (see `keys/storage.ts`) rather than
 * relying on a live in-process timer.
 * @internal
 */
export class KeyManager {
  #state: KeyState | undefined = undefined
  #gracePeriodTimer: ReturnType<typeof setTimeout> | undefined = undefined
  #gracePeriodExpiresAt: number | undefined = undefined

  /** Generate a new 32-byte key with a timestamp-based id. */
  generateKey(): KeyMaterial {
    const randomSuffix = crypto.randomBytes(4).toString('hex')
    return {
      id: `k-${String(Date.now())}-${randomSuffix}`,
      key: new Uint8Array(crypto.randomBytes(32)),
      createdAt: new Date(),
    }
  }

  /**
   * Initialize the manager with a freshly generated key.
   * Safe to call multiple times; subsequent calls are no-ops.
   */
  init(): Promise<void> {
    if (this.#state === undefined) {
      this.#state = { current: this.generateKey() }
    }
    return Promise.resolve()
  }

  /**
   * Replace the in-memory state with a persisted snapshot.
   *
   * An expired grace period in the snapshot is dropped: the previous key is
   * discarded and no grace period is restored. When the grace period is still
   * active, a fresh timer is armed for the remaining duration so the previous
   * key is eventually freed in long-running processes; correctness never depends
   * on that timer (grace is always re-checked against the wall clock).
   * @internal
   */
  hydrate(snapshot: KeyStateSnapshot): void {
    this.#clearGracePeriodTimer()

    if (
      snapshot.previous !== undefined &&
      snapshot.gracePeriodExpiresAt !== undefined &&
      Date.now() < snapshot.gracePeriodExpiresAt
    ) {
      this.#state = { current: snapshot.current, previous: snapshot.previous }
      this.#gracePeriodExpiresAt = snapshot.gracePeriodExpiresAt
      this.#armGracePeriodTimer(snapshot.gracePeriodExpiresAt - Date.now())
    } else {
      this.#state = { current: snapshot.current }
      this.#gracePeriodExpiresAt = undefined
    }
  }

  /**
   * Capture the current state as a serializable snapshot for persistence.
   * The previous key and grace expiry are included only while the grace period
   * is still active.
   * @internal
   */
  snapshot(): KeyStateSnapshot {
    const state = this.#requireState()
    const result: KeyStateSnapshot = { current: state.current }
    const previous = this.getPreviousKey()
    if (previous !== undefined && this.#gracePeriodExpiresAt !== undefined) {
      result.previous = previous
      result.gracePeriodExpiresAt = this.#gracePeriodExpiresAt
    }
    return result
  }

  /** Return the current (encryption) key. Throws if not initialized. */
  getCurrentKey(): KeyMaterial {
    const state = this.#requireState()
    return state.current
  }

  /**
   * Return the previous key if we are still inside a grace period,
   * otherwise `undefined`.
   */
  getPreviousKey(): KeyMaterial | undefined {
    const state = this.#requireState()
    // Grace is authoritative: even if a timer has not yet fired to clear the
    // reference, an expired grace period means the previous key is unusable.
    if (!this.isInGracePeriod()) {
      return undefined
    }
    return state.previous
  }

  /**
   * Find a key by its id, searching current then previous.
   * Returns `undefined` if the key is not found (or the previous key's
   * grace period has expired).
   */
  findKeyById(kid: string): KeyMaterial | undefined {
    const state = this.#requireState()
    if (state.current.id === kid) {
      return state.current
    }
    const previous = this.getPreviousKey()
    if (previous?.id === kid) {
      return previous
    }
    return undefined
  }

  /**
   * Rotate the current key: the current key becomes previous, a new key
   * becomes current. A grace-period timer is started; when it fires the
   * previous key is cleared automatically.
   *
   * @throws {RotationInProgressError} if a rotation is already underway (i.e. a
   *   previous key is still within its grace period).
   */
  rotateKey(gracePeriodMs: number): void {
    const state = this.#requireState()

    if (this.isInGracePeriod()) {
      throw new RotationInProgressError('A key rotation is already in progress')
    }

    // Cancel any stale timer (e.g. from a grace period that has already
    // elapsed) before starting a new rotation.
    this.#clearGracePeriodTimer()

    const newKey = this.generateKey()
    this.#state = { current: newKey, previous: state.current }
    this.#gracePeriodExpiresAt = Date.now() + gracePeriodMs
    this.#armGracePeriodTimer(gracePeriodMs)
  }

  /**
   * Emergency revocation: immediately clear the previous key and generate
   * a brand-new current key. Any in-flight grace period is cancelled.
   */
  revokeKey(): void {
    this.#clearGracePeriodTimer()
    this.#gracePeriodExpiresAt = undefined

    const newKey = this.generateKey()
    this.#state = { current: newKey }
  }

  /**
   * Return `true` while a rotation grace period is active (i.e. the previous
   * key is still accessible).
   */
  isInGracePeriod(): boolean {
    if (this.#gracePeriodExpiresAt === undefined) {
      return false
    }
    return Date.now() < this.#gracePeriodExpiresAt
  }

  // ---------------------------------------------------------------------------
  // Private helpers
  // ---------------------------------------------------------------------------

  #requireState(): KeyState {
    if (this.#state === undefined) {
      throw new SetupError('KeyManager has not been initialized — call init() first', 'KeyManager')
    }
    return this.#state
  }

  #armGracePeriodTimer(delayMs: number): void {
    this.#gracePeriodTimer = setTimeout(() => {
      if (this.#state !== undefined) {
        // Remove the previous key once the grace period elapses.
        this.#state = { current: this.#state.current }
      }
      this.#gracePeriodExpiresAt = undefined
      this.#gracePeriodTimer = undefined
    }, delayMs)

    // Allow the timer to be GC'd without keeping the process alive.
    if (typeof this.#gracePeriodTimer.unref === 'function') {
      this.#gracePeriodTimer.unref()
    }
  }

  #clearGracePeriodTimer(): void {
    if (this.#gracePeriodTimer !== undefined) {
      clearTimeout(this.#gracePeriodTimer)
      this.#gracePeriodTimer = undefined
    }
  }
}
