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
import type { TrustVerificationResult, TrustOptions, PendingTrust } from './types.js'

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
 * Verify the trust tier of the executable at `execPath` without writing
 * anything to the trust manifest.
 *
 * This is the verify phase of the verify/commit split: it computes the
 * executable's hash and classifies it against the existing manifest state,
 * but a first-encounter (Tier 3) or Sigstore (Tier 1) result — which would
 * otherwise record a new hash — is only staged on
 * {@link PendingTrust.pendingWrite}. Nothing is persisted until the caller
 * invokes {@link commitTrust} with the returned value, which callers should do
 * only once the operation the trust decision was gating (e.g. reading the
 * secret) has actually succeeded. This prevents a failed operation from
 * durably pre-seeding TOFU trust for an executable that never completed a
 * legitimate first encounter.
 *
 * A TOFU conflict never stages a write (`pendingWrite` is `undefined`) — the
 * pre-existing manifest state is authoritative and a conflict must always
 * fail without recording the new, unapproved hash.
 *
 * @param execPath - Path to the executable, or `"dev"` to enable dev-mode bypass.
 * @param options  - Optional trust configuration.
 * @internal
 */
export async function verifyTrustPending(
  execPath: string,
  options?: TrustOptions,
): Promise<PendingTrust> {
  const configDir = options?.configDir ?? '.vaultkeeper'

  // Dev-mode bypass: skip all verification for the sentinel value "dev".
  if (execPath === 'dev') {
    return {
      identity: { hash: 'dev', trustTier: 3, verified: false },
      tofuConflict: false,
      approvedHashes: [],
      reason: 'Dev mode — hash verification skipped',
      pendingWrite: undefined,
      configDir,
    }
  }

  const namespace = options?.namespace ?? execPath

  // Compute the current hash of the executable.
  const currentHash = await hashExecutable(execPath)

  // Load the manifest for TOFU and registry checks.
  const manifest = await loadManifest(configDir)

  // Hashes already approved for this namespace (empty on a first encounter).
  const approvedHashes = manifest.get(namespace)?.hashes ?? []

  // --- Tier 1: Sigstore ---
  if (options?.skipSigstore !== true) {
    const sigstoreVerified = await trySigstore(execPath)
    if (sigstoreVerified) {
      return {
        identity: { hash: currentHash, trustTier: 1, verified: true },
        tofuConflict: false,
        approvedHashes,
        reason: 'Sigstore bundle verified',
        pendingWrite: { namespace, hash: currentHash },
        configDir,
      }
    }
  }

  // --- Tier 2: Registry (manifest) ---
  if (isTrusted(manifest, namespace, currentHash)) {
    return {
      identity: { hash: currentHash, trustTier: 2, verified: true },
      tofuConflict: false,
      approvedHashes,
      reason: 'Hash found in trust manifest',
      pendingWrite: undefined,
      configDir,
    }
  }

  // --- TOFU check ---
  const existing = manifest.get(namespace)
  if (existing !== undefined && existing.hashes.length > 0) {
    // The namespace is known but the current hash is not approved — TOFU
    // conflict. Never stage a write: the new hash must not be recorded.
    return {
      identity: { hash: currentHash, trustTier: 3, verified: false },
      tofuConflict: true,
      approvedHashes,
      reason: `Hash changed from a previously approved value — re-approval required`,
      pendingWrite: undefined,
      configDir,
    }
  }

  // --- Tier 3: First encounter — stage the hash for TOFU recording ---
  // `reason` describes staging, not persistence: nothing is written until a
  // caller invokes commitTrust (see PendingTrust.pendingWrite above).
  return {
    identity: { hash: currentHash, trustTier: 3, verified: false },
    tofuConflict: false,
    approvedHashes,
    reason: 'First encounter — hash staged for TOFU recording',
    pendingWrite: { namespace, hash: currentHash },
    configDir,
  }
}

/**
 * Commit phase of the verify/commit split: persist a {@link PendingTrust}'s
 * staged namespace/hash entry, if any.
 *
 * A no-op when {@link PendingTrust.pendingWrite} is `undefined` (a registry
 * match, a TOFU conflict, or dev-mode bypass never write).
 *
 * Verification and commit are not atomic — another process can write to the
 * manifest in between (e.g. approving a different executable, or the same
 * one). To avoid clobbering that concurrent write, this reloads the manifest
 * from disk immediately before saving and unions `pendingWrite` into the
 * *current* state, rather than persisting the snapshot captured back in
 * {@link verifyTrustPending}.
 *
 * @param pending - The result of {@link verifyTrustPending} to commit.
 * @internal
 */
export async function commitTrust(pending: PendingTrust): Promise<void> {
  if (pending.pendingWrite === undefined) {
    return
  }
  const { namespace, hash } = pending.pendingWrite
  const current = await loadManifest(pending.configDir)
  const merged = addTrustedHash(current, namespace, hash)
  await saveManifest(pending.configDir, merged)
}

/**
 * Verify the trust tier of the executable at `execPath`, recording any
 * first-encounter (TOFU) or Sigstore hash immediately.
 *
 * This is an eager convenience wrapper around {@link verifyTrustPending} +
 * {@link commitTrust} for callers that don't need to defer the manifest write
 * until after a later operation succeeds. {@link VaultKeeper.setup} uses the
 * split form directly so a failed `setup()` call never pre-seeds the trust
 * manifest — see issue #148.
 *
 * @param execPath - Path to the executable, or `"dev"` to enable dev-mode bypass.
 * @param options  - Optional trust configuration.
 * @internal
 */
export async function verifyTrust(
  execPath: string,
  options?: TrustOptions,
): Promise<TrustVerificationResult> {
  const pending = await verifyTrustPending(execPath, options)
  await commitTrust(pending)
  const { identity, tofuConflict, approvedHashes, pendingWrite } = pending
  // verifyTrustPending's `reason` describes staging, since verification alone
  // never writes. This wrapper just committed the write above, though, so a
  // first-encounter result should keep its pre-split, persisted-tense wording
  // for existing external callers rather than surfacing "staged" language for
  // something that, by this point, has actually been recorded.
  const reason =
    pendingWrite !== undefined && identity.trustTier === 3
      ? 'First encounter — hash recorded via TOFU'
      : pending.reason
  return { identity, tofuConflict, approvedHashes, reason }
}
