/**
 * Key management for vaultkeeper, including generation, rotation, revocation,
 * and grace-period tracking.
 */

import * as crypto from 'node:crypto'
import { RotationInProgressError, SetupError } from '../errors.js'
import type { KeyMaterial, KeyState } from './types.js'

/**
 * Manage cryptographic keys with rotation and grace-period semantics.
 * @internal
 */
export class KeyManager {
  #state: KeyState | undefined = undefined
  #gracePeriodTimer: ReturnType<typeof setTimeout> | undefined = undefined
  #gracePeriodExpiresAt: number | undefined = undefined
  #rotating = false

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
    const { previous } = state
    if (previous?.id === kid) {
      // previous?.id === kid is only true when previous is defined and its id
      // matches, so we can safely return it here. TypeScript does not narrow
      // the optional-chain result back to KeyMaterial, so we guard explicitly.
      return previous
    }
    return undefined
  }

  /**
   * Rotate the current key: the current key becomes previous, a new key
   * becomes current. A grace-period timer is started; when it fires the
   * previous key is cleared automatically.
   *
   * @throws {RotationInProgressError} if a rotation is already underway.
   */
  rotateKey(gracePeriodMs: number): void {
    if (this.#rotating) {
      throw new RotationInProgressError('A key rotation is already in progress')
    }

    const state = this.#requireState()
    this.#rotating = true

    // Cancel any existing grace-period timer before starting a new rotation.
    this.#clearGracePeriodTimer()

    const newKey = this.generateKey()
    this.#state = { current: newKey, previous: state.current }
    this.#gracePeriodExpiresAt = Date.now() + gracePeriodMs

    this.#gracePeriodTimer = setTimeout(() => {
      if (this.#state !== undefined) {
        // Remove the previous key once the grace period elapses.
        this.#state = { current: this.#state.current }
      }
      this.#gracePeriodExpiresAt = undefined
      this.#gracePeriodTimer = undefined
      this.#rotating = false
    }, gracePeriodMs)

    // Allow the timer to be GC'd without keeping the process alive.
    if (typeof this.#gracePeriodTimer.unref === 'function') {
      this.#gracePeriodTimer.unref()
    }
  }

  /**
   * Emergency revocation: immediately clear the previous key and generate
   * a brand-new current key. Any in-flight grace period is cancelled.
   */
  revokeKey(): void {
    this.#clearGracePeriodTimer()
    this.#rotating = false
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
      throw new SetupError(
        'KeyManager has not been initialized — call init() first',
        'KeyManager',
      )
    }
    return this.#state
  }

  #clearGracePeriodTimer(): void {
    if (this.#gracePeriodTimer !== undefined) {
      clearTimeout(this.#gracePeriodTimer)
      this.#gracePeriodTimer = undefined
    }
  }
}
