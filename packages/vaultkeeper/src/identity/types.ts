/**
 * Types for the executable identity and trust layer.
 */

import type { TrustTier, VaultClaims } from '../types.js'

export type { TrustTier }

/**
 * Identity information about a verified executable.
 * @internal
 */
export interface IdentityInfo {
  /** SHA-256 hex digest of the executable binary. */
  hash: string
  /** Achieved trust tier for this executable. */
  trustTier: TrustTier
  /** Whether the identity was positively verified (not merely observed). */
  verified: boolean
}

/**
 * Result returned by `verifyTrust`.
 * @internal
 */
export interface TrustVerificationResult {
  /** The computed identity information. */
  identity: IdentityInfo
  /**
   * True when TOFU (trust-on-first-use) detected a hash change.
   * When true, the caller must prompt for re-approval before proceeding.
   */
  tofuConflict: boolean
  /** Human-readable description of how trust was established. */
  reason: string
}

/**
 * Options controlling how trust verification is performed.
 * @internal
 */
export interface TrustOptions {
  /**
   * Directory where the trust manifest is stored.
   * Defaults to the process config dir when omitted.
   */
  configDir?: string | undefined
  /**
   * Namespace used for TOFU and manifest lookups.
   * Typically the CLI name or a stable identifier for the executable.
   */
  namespace?: string | undefined
  /**
   * When `true`, skip Sigstore verification even if the package is installed.
   * Useful in offline environments.
   */
  skipSigstore?: boolean | undefined
}

/**
 * Per-namespace entry in the trust manifest.
 * @internal
 */
export interface TrustManifestEntry {
  /** Approved hashes for this namespace. */
  hashes: string[]
  /** Trust tier recorded when the hash was first approved. */
  trustTier: TrustTier
}

/**
 * The on-disk trust manifest.
 * Maps a namespace string to its approved-hash entry.
 * @internal
 */
export type TrustManifest = Map<string, TrustManifestEntry>

/** Re-export `VaultClaims` for use in session module. */
export type { VaultClaims }
