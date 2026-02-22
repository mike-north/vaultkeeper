import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import * as fs from 'node:fs/promises'
import * as path from 'node:path'
import * as os from 'node:os'
import { getCacheDir, readCachedToken, writeCachedToken, invalidateCache } from '../../src/cache.js'

describe('cache read/write/invalidate', () => {
  let tmpDir: string

  beforeEach(async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'vaultkeeper-cache-test-'))
    vi.stubEnv('XDG_RUNTIME_DIR', tmpDir)
  })

  afterEach(async () => {
    vi.unstubAllEnvs()
    await fs.rm(tmpDir, { recursive: true, force: true })
  })

  it('should return undefined for a missing cache entry', async () => {
    const result = await readCachedToken('/usr/bin/test', 'my-secret')
    expect(result).toBeUndefined()
  })

  it('should write and read a cached token', async () => {
    const jwe = 'eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..test-jwe-token'
    await writeCachedToken('/usr/bin/test', 'my-secret', jwe)
    const result = await readCachedToken('/usr/bin/test', 'my-secret')
    expect(result).toBe(jwe)
  })

  it('should invalidate a cached token', async () => {
    await writeCachedToken('/usr/bin/test', 'my-secret', 'token')
    await invalidateCache('/usr/bin/test', 'my-secret')
    const result = await readCachedToken('/usr/bin/test', 'my-secret')
    expect(result).toBeUndefined()
  })

  it('should not throw when invalidating a non-existent entry', async () => {
    await expect(invalidateCache('/nope', 'nope')).resolves.toBeUndefined()
  })

  it('should use different cache files for different caller/secret pairs', async () => {
    await writeCachedToken('/a', 'secret1', 'token-a')
    await writeCachedToken('/b', 'secret2', 'token-b')
    expect(await readCachedToken('/a', 'secret1')).toBe('token-a')
    expect(await readCachedToken('/b', 'secret2')).toBe('token-b')
  })

  it('should create cache directory with mode 0o700', async () => {
    await writeCachedToken('/usr/bin/test', 'my-secret', 'token')
    const dir = getCacheDir()
    const stat = await fs.stat(dir)
    // Check owner-only rwx (0o700), masking out file type bits
    expect(stat.mode & 0o777).toBe(0o700)
  })

  it('should write cache file with mode 0o600', async () => {
    const jwe = 'test-token'
    await writeCachedToken('/usr/bin/test', 'my-secret', jwe)
    const dir = getCacheDir()
    const files = await fs.readdir(dir)
    expect(files).toHaveLength(1)
    const fileName = files[0]
    expect(fileName).toBeDefined()
    const filePath = path.join(dir, fileName ?? '')
    const stat = await fs.stat(filePath)
    expect(stat.mode & 0o777).toBe(0o600)
  })

  it('should return undefined for an empty cache file', async () => {
    // Simulate a corrupted/empty cache file
    const dir = getCacheDir()
    await fs.mkdir(dir, { recursive: true, mode: 0o700 })
    // Write a token first to learn the filename, then truncate it
    await writeCachedToken('/usr/bin/test', 'empty-secret', 'placeholder')
    const files = await fs.readdir(dir)
    expect(files).toHaveLength(1)
    const firstFile = files[0]
    expect(firstFile).toBeDefined()
    await fs.writeFile(path.join(dir, firstFile ?? ''), '', { encoding: 'utf8' })
    const result = await readCachedToken('/usr/bin/test', 'empty-secret')
    expect(result).toBeUndefined()
  })
})

describe('getCacheDir', () => {
  afterEach(() => {
    vi.unstubAllEnvs()
  })

  it('should use XDG_RUNTIME_DIR when set', () => {
    vi.stubEnv('XDG_RUNTIME_DIR', '/run/user/1000')
    expect(getCacheDir()).toBe('/run/user/1000/vaultkeeper')
  })

  it('should fall back to tmpdir when XDG_RUNTIME_DIR is empty string', () => {
    vi.stubEnv('XDG_RUNTIME_DIR', '')
    const result = getCacheDir()
    expect(result).toContain('vaultkeeper-')
    expect(result.startsWith(os.tmpdir())).toBe(true)
  })

  it('should fall back to tmpdir when XDG_RUNTIME_DIR is not set', () => {
    vi.stubEnv('XDG_RUNTIME_DIR', '')
    const result = getCacheDir()
    expect(result).toContain(os.tmpdir())
  })
})
