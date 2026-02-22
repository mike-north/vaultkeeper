/**
 * Trust classification for executables.
 *
 * Tier 1 — Sigstore: cryptographic provenance verified via Sigstore (lazy import).
 * Tier 2 — Registry: hash found in the approved trust manifest.
 * Tier 3 — Unverified: default fallback when no stronger evidence is available.
 *
 * TOFU (Trust On First Use): on the first encounter with an executable the hash
 * is recorded. If the hash changes on a subsequent call a `tofuConflict` is
 * signalled so the caller can prompt for re-approval.
 *
 * Dev-mode bypass: when the executable path is the literal string `"dev"` all
 * hash verification is skipped and Tier 3 unverified is returned immediately.
 */

import { hashExecutable } from './hash.js'
import { loadManifest, saveManifest, addTrustedHash, isTrusted } from './manifest.js'
import type { TrustVerificationResult, TrustOptions } from './types.js'

/** Attempt Sigstore bundle verification (Tier 1). Returns `true` on success. */
async function trySigstore(execPath: string): Promise<boolean> {
  try {
    // Dynamic import so the library works without sigstore installed.
    // @ts-expect-error — sigstore is an optional peer dependency not listed in
    // package.json; the import will fail at runtime if not installed, which is
    // the intended behaviour. We catch that case below.
    const sigstore: unknown = await import('sigstore')
    // sigstore.verify expects a bundle; for executable verification we check
    // whether the library is present and functional. If the import succeeds but
    // the verify function is not available we fall through gracefully.
    if (typeof sigstore !== 'object' || sigstore === null) {
      return false
    }
    if (!('verify' in sigstore) || typeof sigstore.verify !== 'function') {
      return false
    }
    // Executable bundles are not universally available; treat any error as a
    // Tier-1 failure rather than a hard error.
    void execPath // execPath would be used in a full Sigstore bundle lookup
    return false // Full Sigstore bundle verification not yet available for arbitrary binaries
  } catch {
    return false
  }
}

/**
 * Verify the trust tier of the executable at `execPath`.
 *
 * @param execPath - Path to the executable, or `"dev"` to enable dev-mode bypass.
 * @param options  - Optional trust configuration.
 * @internal
 */
export async function verifyTrust(
  execPath: string,
  options?: TrustOptions,
): Promise<TrustVerificationResult> {
  // Dev-mode bypass: skip all verification for the sentinel value "dev".
  if (execPath === 'dev') {
    return {
      identity: { hash: 'dev', trustTier: 3, verified: false },
      tofuConflict: false,
      reason: 'Dev mode — hash verification skipped',
    }
  }

  const configDir = options?.configDir ?? '.vaultkeeper'
  const namespace = options?.namespace ?? execPath

  // Compute the current hash of the executable.
  const currentHash = await hashExecutable(execPath)

  // Load the manifest for TOFU and registry checks.
  const manifest = await loadManifest(configDir)

  // --- Tier 1: Sigstore ---
  if (options?.skipSigstore !== true) {
    const sigstoreVerified = await trySigstore(execPath)
    if (sigstoreVerified) {
      const updated = addTrustedHash(manifest, namespace, currentHash)
      await saveManifest(configDir, updated)
      return {
        identity: { hash: currentHash, trustTier: 1, verified: true },
        tofuConflict: false,
        reason: 'Sigstore bundle verified',
      }
    }
  }

  // --- Tier 2: Registry (manifest) ---
  if (isTrusted(manifest, namespace, currentHash)) {
    return {
      identity: { hash: currentHash, trustTier: 2, verified: true },
      tofuConflict: false,
      reason: 'Hash found in trust manifest',
    }
  }

  // --- TOFU check ---
  const existing = manifest.get(namespace)
  if (existing !== undefined && existing.hashes.length > 0) {
    // The namespace is known but the current hash is not approved — TOFU conflict.
    return {
      identity: { hash: currentHash, trustTier: 3, verified: false },
      tofuConflict: true,
      reason: `Hash changed from a previously approved value — re-approval required`,
    }
  }

  // --- Tier 3: First encounter — record via TOFU ---
  const updated = addTrustedHash(manifest, namespace, currentHash)
  await saveManifest(configDir, updated)
  return {
    identity: { hash: currentHash, trustTier: 3, verified: false },
    tofuConflict: false,
    reason: 'First encounter — hash recorded via TOFU',
  }
}
