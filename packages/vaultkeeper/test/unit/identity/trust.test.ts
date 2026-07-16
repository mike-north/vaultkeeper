import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import * as fs from 'node:fs/promises'
import * as os from 'node:os'
import * as path from 'node:path'
import { verifyTrust, verifyTrustPending, commitTrust } from '../../../src/identity/trust.js'
import { loadManifest, addTrustedHash, saveManifest } from '../../../src/identity/manifest.js'
import { IdentityMismatchError } from '../../../src/errors.js'

async function withTempDir(fn: (dir: string) => Promise<void>): Promise<void> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'vaultkeeper-trust-'))
  try {
    await fn(dir)
  } finally {
    await fs.rm(dir, { recursive: true })
  }
}

async function createTempBinary(dir: string, name: string, content: string): Promise<string> {
  const filePath = path.join(dir, name)
  await fs.writeFile(filePath, content, 'utf8')
  return filePath
}

let tempDir: string

beforeEach(async () => {
  tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'vaultkeeper-trust-'))
})

afterEach(async () => {
  await fs.rm(tempDir, { recursive: true })
})

describe('verifyTrust — dev mode bypass', () => {
  it('returns tier 3 unverified immediately for "dev" exe path', async () => {
    const result = await verifyTrust('dev', { configDir: tempDir })
    expect(result.identity.hash).toBe('dev')
    expect(result.identity.trustTier).toBe(3)
    expect(result.identity.verified).toBe(false)
    expect(result.tofuConflict).toBe(false)
    expect(result.reason).toContain('Dev mode')
  })

  it('does not write to the manifest in dev mode', async () => {
    await verifyTrust('dev', { configDir: tempDir })
    const manifest = await loadManifest(tempDir)
    expect(manifest.size).toBe(0)
  })
})

describe('verifyTrust — Tier 3 (first encounter / TOFU)', () => {
  it('records the hash on first encounter and returns tier 3', async () => {
    await withTempDir(async (dir) => {
      const execPath = await createTempBinary(dir, 'my-tool', 'binary-content-v1')
      const configDir = path.join(dir, 'config')
      const result = await verifyTrust(execPath, {
        configDir,
        namespace: 'my-tool',
        skipSigstore: true,
      })

      expect(result.identity.trustTier).toBe(3)
      expect(result.identity.verified).toBe(false)
      expect(result.tofuConflict).toBe(false)
      expect(result.reason).toContain('TOFU')

      const manifest = await loadManifest(configDir)
      expect(manifest.has('my-tool')).toBe(true)
    })
  })
})

describe('verifyTrust — Tier 2 (registry / manifest)', () => {
  it('returns tier 2 verified when hash is in the manifest', async () => {
    await withTempDir(async (dir) => {
      const execPath = await createTempBinary(dir, 'trusted-tool', 'trusted-binary-content')
      const configDir = path.join(dir, 'config')

      // First call records it
      await verifyTrust(execPath, { configDir, namespace: 'trusted-tool', skipSigstore: true })

      // Second call: hash is now known
      const result = await verifyTrust(execPath, {
        configDir,
        namespace: 'trusted-tool',
        skipSigstore: true,
      })
      expect(result.identity.trustTier).toBe(2)
      expect(result.identity.verified).toBe(true)
      expect(result.tofuConflict).toBe(false)
      expect(result.reason).toContain('manifest')
    })
  })
})

describe('verifyTrust — TOFU conflict', () => {
  it('signals tofuConflict when the hash changes after initial recording', async () => {
    await withTempDir(async (dir) => {
      const execPath = await createTempBinary(dir, 'changing-tool', 'version-1')
      const configDir = path.join(dir, 'config')

      // Record v1 hash
      const first = await verifyTrust(execPath, {
        configDir,
        namespace: 'changing-tool',
        skipSigstore: true,
      })
      const v1Hash = first.identity.hash

      // Overwrite with different content (simulating a binary update or tampering)
      await fs.writeFile(execPath, 'version-2', 'utf8')

      const result = await verifyTrust(execPath, {
        configDir,
        namespace: 'changing-tool',
        skipSigstore: true,
      })
      expect(result.tofuConflict).toBe(true)
      expect(result.identity.trustTier).toBe(3)
      expect(result.identity.verified).toBe(false)
      expect(result.reason).toContain('re-approval')
      // The conflict surfaces the previously approved hash(es), not a placeholder.
      expect(result.approvedHashes).toEqual([v1Hash])
      expect(result.identity.hash).not.toBe(v1Hash)
    })
  })

  it('does not write the new hash to the manifest when tofuConflict is true', async () => {
    await withTempDir(async (dir) => {
      const execPath = await createTempBinary(dir, 'tampered', 'original')
      const configDir = path.join(dir, 'config')

      // Record original
      const first = await verifyTrust(execPath, {
        configDir,
        namespace: 'tampered',
        skipSigstore: true,
      })
      const originalHash = first.identity.hash

      // Change binary
      await fs.writeFile(execPath, 'tampered-content', 'utf8')
      await verifyTrust(execPath, { configDir, namespace: 'tampered', skipSigstore: true })

      // Manifest should still only contain the original hash
      const manifest = await loadManifest(configDir)
      const entry = manifest.get('tampered')
      expect(entry?.hashes).toEqual([originalHash])
    })
  })
})

describe('verifyTrust — namespace handling', () => {
  it('uses execPath as namespace when namespace option is omitted', async () => {
    await withTempDir(async (dir) => {
      const execPath = await createTempBinary(dir, 'ns-tool', 'content')
      const configDir = path.join(dir, 'config')

      await verifyTrust(execPath, { configDir, skipSigstore: true })

      const manifest = await loadManifest(configDir)
      expect(manifest.has(execPath)).toBe(true)
    })
  })

  it('uses configured namespace when provided', async () => {
    await withTempDir(async (dir) => {
      const execPath = await createTempBinary(dir, 'ns-tool-b', 'content')
      const configDir = path.join(dir, 'config')

      await verifyTrust(execPath, { configDir, namespace: 'custom-namespace', skipSigstore: true })

      const manifest = await loadManifest(configDir)
      expect(manifest.has('custom-namespace')).toBe(true)
      expect(manifest.has(execPath)).toBe(false)
    })
  })
})

describe('verifyTrustPending / commitTrust — verify/commit split (#148)', () => {
  it('verifyTrustPending stages a first-encounter hash but does not write it', async () => {
    await withTempDir(async (dir) => {
      const execPath = await createTempBinary(dir, 'my-tool', 'binary-content-v1')
      const configDir = path.join(dir, 'config')

      const pending = await verifyTrustPending(execPath, {
        configDir,
        namespace: 'my-tool',
        skipSigstore: true,
      })

      expect(pending.identity.trustTier).toBe(3)
      expect(pending.tofuConflict).toBe(false)
      expect(pending.pendingWrite).toEqual({ namespace: 'my-tool', hash: pending.identity.hash })
      // The verify phase hasn't written anything yet, so `reason` must not
      // claim persistence — it describes staging, not recording.
      expect(pending.reason).toContain('staged')
      expect(pending.reason).not.toContain('recorded')

      // Nothing was written by the verify phase alone.
      const manifest = await loadManifest(configDir)
      expect(manifest.size).toBe(0)
    })
  })

  it('commitTrust persists a staged first-encounter hash', async () => {
    await withTempDir(async (dir) => {
      const execPath = await createTempBinary(dir, 'my-tool', 'binary-content-v1')
      const configDir = path.join(dir, 'config')

      const pending = await verifyTrustPending(execPath, {
        configDir,
        namespace: 'my-tool',
        skipSigstore: true,
      })
      await commitTrust(pending)

      const manifest = await loadManifest(configDir)
      expect(manifest.has('my-tool')).toBe(true)
    })
  })

  it('commitTrust is a no-op when pendingWrite is undefined (e.g. a TOFU conflict)', async () => {
    await withTempDir(async (dir) => {
      const execPath = await createTempBinary(dir, 'tampered', 'original')
      const configDir = path.join(dir, 'config')

      // Record the original hash so the next call is a conflict, not a first
      // encounter.
      await verifyTrust(execPath, { configDir, namespace: 'tampered', skipSigstore: true })
      await fs.writeFile(execPath, 'tampered-content', 'utf8')

      const pending = await verifyTrustPending(execPath, {
        configDir,
        namespace: 'tampered',
        skipSigstore: true,
      })
      expect(pending.tofuConflict).toBe(true)
      expect(pending.pendingWrite).toBeUndefined()

      // Committing a conflict result must not throw and must not write.
      await commitTrust(pending)
      const manifest = await loadManifest(configDir)
      expect(manifest.get('tampered')?.hashes).toEqual([pending.approvedHashes.at(-1)])
    })
  })

  it('a registry (Tier 2) match stages nothing to commit', async () => {
    await withTempDir(async (dir) => {
      const execPath = await createTempBinary(dir, 'trusted-tool', 'trusted-binary-content')
      const configDir = path.join(dir, 'config')

      await verifyTrust(execPath, { configDir, namespace: 'trusted-tool', skipSigstore: true })

      const pending = await verifyTrustPending(execPath, {
        configDir,
        namespace: 'trusted-tool',
        skipSigstore: true,
      })
      expect(pending.identity.trustTier).toBe(2)
      expect(pending.pendingWrite).toBeUndefined()
    })
  })

  // Verification and commit are not atomic: another process can write to the
  // manifest in between (e.g. approving a different executable while our
  // setup() call is still retrieving its secret). commitTrust must reload the
  // manifest at commit time and merge the staged entry in, not persist the
  // stale snapshot captured during verifyTrustPending — otherwise the
  // concurrent write would be silently clobbered.
  it('commitTrust merges with a concurrent manifest write instead of clobbering it', async () => {
    await withTempDir(async (dir) => {
      const execPath = await createTempBinary(dir, 'my-tool', 'binary-content-v1')
      const configDir = path.join(dir, 'config')

      const pending = await verifyTrustPending(execPath, {
        configDir,
        namespace: 'my-tool',
        skipSigstore: true,
      })

      // Simulate a concurrent process approving a different executable
      // between our verify phase and our commit.
      const concurrentManifest = await loadManifest(configDir)
      const withConcurrentEntry = addTrustedHash(
        concurrentManifest,
        'other-tool',
        'concurrent-hash',
      )
      await saveManifest(configDir, withConcurrentEntry)

      await commitTrust(pending)

      // Both the concurrent entry and our staged entry must survive.
      const manifest = await loadManifest(configDir)
      expect(manifest.get('other-tool')?.hashes).toEqual(['concurrent-hash'])
      expect(manifest.has('my-tool')).toBe(true)
    })
  })

  // Issue #223 (mirrors Rust fix c46913d, #213 review follow-up): a *late*
  // TOFU conflict. If a concurrent process records a DIFFERENT hash for the
  // SAME namespace in the window between verify and commit, blindly merging
  // the staged hash would silently approve a second hash for one namespace —
  // bypassing the TOFU-conflict record-nothing rule enforced at verify time
  // (issue #148). commitTrust must re-classify against the freshly reloaded
  // manifest and refuse: throw IdentityMismatchError and write nothing.
  it('commitTrust refuses when a concurrent process recorded a different hash for the same namespace', async () => {
    await withTempDir(async (dir) => {
      const execPath = await createTempBinary(dir, 'my-tool', 'binary-content-v1')
      const configDir = path.join(dir, 'config')

      const pending = await verifyTrustPending(execPath, {
        configDir,
        namespace: 'my-tool',
        skipSigstore: true,
      })
      const stagedHash = pending.identity.hash

      // Simulate a concurrent process recording a DIFFERENT hash for the SAME
      // namespace before our commit reloads the manifest.
      const concurrentManifest = await loadManifest(configDir)
      const withOtherHash = addTrustedHash(concurrentManifest, 'my-tool', 'concurrent-hash-b')
      await saveManifest(configDir, withOtherHash)

      await expect(commitTrust(pending)).rejects.toThrow(IdentityMismatchError)

      // Nothing was written beyond the concurrent entry: our staged hash never
      // landed, and the namespace still has only one approved hash.
      const manifest = await loadManifest(configDir)
      expect(manifest.get('my-tool')?.hashes).toEqual(['concurrent-hash-b'])
      expect(manifest.get('my-tool')?.hashes).not.toContain(stagedHash)
    })
  })

  it('commitTrust throws IdentityMismatchError carrying the previous and staged hashes', async () => {
    await withTempDir(async (dir) => {
      const execPath = await createTempBinary(dir, 'my-tool', 'binary-content-v1')
      const configDir = path.join(dir, 'config')

      const pending = await verifyTrustPending(execPath, {
        configDir,
        namespace: 'my-tool',
        skipSigstore: true,
      })
      const stagedHash = pending.identity.hash

      const concurrentManifest = await loadManifest(configDir)
      const withOtherHash = addTrustedHash(concurrentManifest, 'my-tool', 'concurrent-hash-b')
      await saveManifest(configDir, withOtherHash)

      let caught: unknown
      try {
        await commitTrust(pending)
      } catch (err) {
        caught = err
      }
      if (!(caught instanceof IdentityMismatchError)) {
        throw new Error(
          `expected commitTrust to throw IdentityMismatchError, got: ${String(caught)}`,
        )
      }
      expect(caught.previousHash).toBe('concurrent-hash-b')
      expect(caught.currentHash).toBe(stagedHash)
    })
  })

  it('verifyTrust (eager wrapper) still verifies and commits in one call', async () => {
    await withTempDir(async (dir) => {
      const execPath = await createTempBinary(dir, 'my-tool', 'binary-content-v1')
      const configDir = path.join(dir, 'config')

      const result = await verifyTrust(execPath, {
        configDir,
        namespace: 'my-tool',
        skipSigstore: true,
      })

      expect(result.identity.trustTier).toBe(3)
      const manifest = await loadManifest(configDir)
      expect(manifest.has('my-tool')).toBe(true)
      // A write actually happened by the time this eager wrapper returns, so
      // external callers should keep seeing the pre-split, persisted-tense
      // wording — not the verify phase's "staged" language.
      expect(result.reason).toBe('First encounter — hash recorded via TOFU')
    })
  })
})

describe('verifyTrust — Sigstore skipping', () => {
  it('skips Sigstore when skipSigstore is true', async () => {
    await withTempDir(async (dir) => {
      const execPath = await createTempBinary(dir, 'sig-skip-tool', 'content')
      const configDir = path.join(dir, 'config')

      // Should not throw even if sigstore is unavailable
      const result = await verifyTrust(execPath, {
        configDir,
        namespace: 'sig-skip',
        skipSigstore: true,
      })
      // Result should be tier 3 (TOFU first use) since we skipped Sigstore
      expect(result.identity.trustTier).toBe(3)
    })
  })
})
