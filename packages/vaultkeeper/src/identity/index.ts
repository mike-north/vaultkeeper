/**
 * Executable identity and trust layer barrel export.
 */

export type {
  IdentityInfo,
  TrustVerificationResult,
  PendingTrust,
  TrustOptions,
  TrustManifestEntry,
  TrustManifest,
} from './types.js'

export { hashExecutable } from './hash.js'

export { loadManifest, saveManifest, addTrustedHash, isTrusted } from './manifest.js'

export { verifyTrust, verifyTrustPending, commitTrust } from './trust.js'

export { CapabilityToken, createCapabilityToken, validateCapabilityToken } from './session.js'
