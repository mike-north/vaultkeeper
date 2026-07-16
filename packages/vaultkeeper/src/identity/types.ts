/**
 * Types for the executable identity and trust layer.
 */

import type { TrustTier, VaultClaims, SigningClaims } from '../types.js'

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
  /**
   * Hashes already recorded in the trust manifest for this namespace at the
   * time of verification, in approval order (empty on a first encounter). On a
   * {@link TrustVerificationResult.tofuConflict}, these are the previously
   * approved values that the current on-disk hash no longer matches.
   */
  approvedHashes: string[]
  /** Human-readable description of how trust was established. */
  reason: string
}

/**
 * Result of the verify-only phase of trust verification (see
 * {@link verifyTrustPending}). No manifest write has happened yet — pass this
 * to {@link commitTrust} once the caller's operation has actually succeeded to
 * persist the pending update, or discard it to leave the manifest untouched.
 * @internal
 */
export interface PendingTrust extends TrustVerificationResult {
  /**
   * The manifest state to persist once the caller's operation succeeds, or
   * `undefined` when this verification produced no manifest change — a
   * registry (Tier 2) match, a TOFU conflict, or dev-mode bypass never write.
   */
  readonly manifestToSave: TrustManifest | undefined
  /** Directory {@link commitTrust} writes `manifestToSave` to, if present. */
  readonly configDir: string
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

/** Re-export claim shapes for use in the session module. */
export type { VaultClaims, SigningClaims }
