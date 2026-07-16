import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import * as fs from 'node:fs/promises'
import * as os from 'node:os'
import * as path from 'node:path'
import { verifyTrust, verifyTrustPending, commitTrust } from '../../../src/identity/trust.js'
import { loadManifest } from '../../../src/identity/manifest.js'

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
      expect(pending.manifestToSave).toBeDefined()
      expect(pending.manifestToSave?.has('my-tool')).toBe(true)

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

  it('commitTrust is a no-op when manifestToSave is undefined (e.g. a TOFU conflict)', async () => {
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
      expect(pending.manifestToSave).toBeUndefined()

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
      expect(pending.manifestToSave).toBeUndefined()
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
