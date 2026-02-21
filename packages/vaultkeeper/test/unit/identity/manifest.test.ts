import { describe, it, expect } from 'vitest'
import * as fs from 'node:fs/promises'
import * as os from 'node:os'
import * as path from 'node:path'
import {
  loadManifest,
  saveManifest,
  addTrustedHash,
  isTrusted,
} from '../../../src/identity/manifest.js'
import type { TrustManifest } from '../../../src/identity/types.js'

async function withTempDir(fn: (dir: string) => Promise<void>): Promise<void> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'vaultkeeper-manifest-'))
  try {
    await fn(dir)
  } finally {
    await fs.rm(dir, { recursive: true })
  }
}

describe('loadManifest', () => {
  it('returns an empty Map when the manifest file does not exist', async () => {
    await withTempDir(async (dir) => {
      const manifest = await loadManifest(dir)
      expect(manifest.size).toBe(0)
    })
  })

  it('loads a saved manifest back correctly', async () => {
    await withTempDir(async (dir) => {
      const original: TrustManifest = new Map([
        ['my-cli', { hashes: ['abc123', 'def456'], trustTier: 2 }],
      ])
      await saveManifest(dir, original)
      const loaded = await loadManifest(dir)
      expect(loaded.size).toBe(1)
      const entry = loaded.get('my-cli')
      expect(entry).toBeDefined()
      expect(entry?.hashes).toEqual(['abc123', 'def456'])
      expect(entry?.trustTier).toBe(2)
    })
  })

  it('throws for a corrupt manifest file', async () => {
    await withTempDir(async (dir) => {
      const manifestPath = path.join(dir, 'trust-manifest.json')
      await fs.writeFile(manifestPath, 'not valid json!!', 'utf8')
      await expect(loadManifest(dir)).rejects.toThrow()
    })
  })

  it('ignores entries with invalid trust tiers', async () => {
    await withTempDir(async (dir) => {
      const raw = JSON.stringify({
        version: 1,
        entries: {
          valid: { hashes: ['aaa'], trustTier: 2 },
          invalid: { hashes: ['bbb'], trustTier: 99 },
        },
      })
      const manifestPath = path.join(dir, 'trust-manifest.json')
      await fs.writeFile(manifestPath, raw, 'utf8')
      const loaded = await loadManifest(dir)
      expect(loaded.has('valid')).toBe(true)
      expect(loaded.has('invalid')).toBe(false)
    })
  })
})

describe('saveManifest', () => {
  it('creates the config directory if it does not exist', async () => {
    await withTempDir(async (dir) => {
      const subDir = path.join(dir, 'nested', 'config')
      const manifest: TrustManifest = new Map()
      await saveManifest(subDir, manifest)
      const stat = await fs.stat(subDir)
      expect(stat.isDirectory()).toBe(true)
    })
  })

  it('writes a readable JSON file', async () => {
    await withTempDir(async (dir) => {
      const manifest: TrustManifest = new Map([
        ['tool', { hashes: ['hash1'], trustTier: 3 }],
      ])
      await saveManifest(dir, manifest)
      const raw = await fs.readFile(path.join(dir, 'trust-manifest.json'), 'utf8')
      const parsed: unknown = JSON.parse(raw)
      expect(parsed).toMatchObject({ version: 1 })
    })
  })

  it('overwrites the existing manifest', async () => {
    await withTempDir(async (dir) => {
      const first: TrustManifest = new Map([['a', { hashes: ['h1'], trustTier: 2 }]])
      await saveManifest(dir, first)
      const second: TrustManifest = new Map([['b', { hashes: ['h2'], trustTier: 3 }]])
      await saveManifest(dir, second)
      const loaded = await loadManifest(dir)
      expect(loaded.has('a')).toBe(false)
      expect(loaded.has('b')).toBe(true)
    })
  })
})

describe('addTrustedHash', () => {
  it('creates a new entry with tier 3 when the namespace does not exist', () => {
    const manifest: TrustManifest = new Map()
    const updated = addTrustedHash(manifest, 'new-ns', 'abc')
    expect(updated.get('new-ns')).toEqual({ hashes: ['abc'], trustTier: 3 })
  })

  it('appends a hash to an existing namespace without changing the tier', () => {
    const manifest: TrustManifest = new Map([['ns', { hashes: ['old'], trustTier: 2 }]])
    const updated = addTrustedHash(manifest, 'ns', 'new')
    expect(updated.get('ns')?.hashes).toEqual(['old', 'new'])
    expect(updated.get('ns')?.trustTier).toBe(2)
  })

  it('does not add a duplicate hash', () => {
    const manifest: TrustManifest = new Map([['ns', { hashes: ['hash'], trustTier: 2 }]])
    const updated = addTrustedHash(manifest, 'ns', 'hash')
    expect(updated.get('ns')?.hashes).toEqual(['hash'])
  })

  it('does not mutate the original manifest', () => {
    const manifest: TrustManifest = new Map()
    addTrustedHash(manifest, 'ns', 'hash')
    expect(manifest.size).toBe(0)
  })

  it('preserves entries for other namespaces', () => {
    const manifest: TrustManifest = new Map([['other', { hashes: ['x'], trustTier: 1 }]])
    const updated = addTrustedHash(manifest, 'new-ns', 'y')
    expect(updated.get('other')).toEqual({ hashes: ['x'], trustTier: 1 })
  })
})

describe('isTrusted', () => {
  it('returns true when the hash is in the approved list', () => {
    const manifest: TrustManifest = new Map([['ns', { hashes: ['aaa', 'bbb'], trustTier: 2 }]])
    expect(isTrusted(manifest, 'ns', 'aaa')).toBe(true)
    expect(isTrusted(manifest, 'ns', 'bbb')).toBe(true)
  })

  it('returns false when the hash is not in the approved list', () => {
    const manifest: TrustManifest = new Map([['ns', { hashes: ['aaa'], trustTier: 2 }]])
    expect(isTrusted(manifest, 'ns', 'zzz')).toBe(false)
  })

  it('returns false for an unknown namespace', () => {
    const manifest: TrustManifest = new Map()
    expect(isTrusted(manifest, 'unknown', 'aaa')).toBe(false)
  })

  it('returns false for an empty hash list', () => {
    const manifest: TrustManifest = new Map([['ns', { hashes: [], trustTier: 3 }]])
    expect(isTrusted(manifest, 'ns', 'aaa')).toBe(false)
  })
})
