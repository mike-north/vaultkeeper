/**
 * Key management types for vaultkeeper.
 */

/** A cryptographic key with metadata. */
export interface KeyMaterial {
  /** Unique identifier, format: `k-{timestamp}` */
  id: string
  /** 32-byte raw key material */
  key: Uint8Array
  /** When the key was generated */
  createdAt: Date
}

/** The active state of the key pair (current + optional previous in grace period). */
export interface KeyState {
  /** The currently active key for encryption */
  current: KeyMaterial
  /** The previous key, only present during a grace period */
  previous?: KeyMaterial
}

/** Configuration for key rotation behavior. */
export interface KeyRotationConfig {
  /** How long (in milliseconds) the previous key remains valid after rotation */
  gracePeriodMs: number
}
