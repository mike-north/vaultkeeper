/**
 * Key management types for vaultkeeper.
 */

/**
 * A cryptographic key with metadata.
 * @internal
 */
export interface KeyMaterial {
  /** Unique identifier, format: `k-{timestamp}` */
  id: string
  /** 32-byte raw key material */
  key: Uint8Array
  /** When the key was generated */
  createdAt: Date
}

/**
 * The active state of the key pair (current + optional previous in grace period).
 * @internal
 */
export interface KeyState {
  /** The currently active key for encryption */
  current: KeyMaterial
  /** The previous key, only present during a grace period */
  previous?: KeyMaterial
}

/**
 * Configuration for key rotation behavior.
 * @internal
 */
export interface KeyRotationConfig {
  /** How long (in milliseconds) the previous key remains valid after rotation */
  gracePeriodMs: number
}

/**
 * A point-in-time snapshot of {@link KeyManager} state, suitable for persisting
 * across processes. Produced by {@link KeyManager.snapshot} and consumed by
 * {@link KeyManager.hydrate}.
 *
 * The rotation grace period is represented purely as an absolute expiry
 * timestamp; whether a rotation is "in progress" is derived by comparing it to
 * the current time, so the guard survives process restarts without a live
 * timer.
 * @internal
 */
export interface KeyStateSnapshot {
  /** The currently active encryption key. */
  current: KeyMaterial
  /** The previous key, present only while its grace period is still active. */
  previous?: KeyMaterial
  /**
   * Absolute epoch-millisecond time at which the current grace period ends.
   * Present only while a rotation grace period is active.
   */
  gracePeriodExpiresAt?: number
}
