import { describe, it, expect } from 'vitest'
import * as fs from 'node:fs/promises'
import * as os from 'node:os'
import * as path from 'node:path'
import { hashExecutable } from '../../../src/identity/hash.js'

async function withTempFile(content: string, fn: (filePath: string) => Promise<void>): Promise<void> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'vaultkeeper-hash-'))
  const filePath = path.join(dir, 'test-binary')
  try {
    await fs.writeFile(filePath, content, 'utf8')
    await fn(filePath)
  } finally {
    await fs.rm(dir, { recursive: true })
  }
}

describe('hashExecutable', () => {
  it('produces a 64-character hex string for a non-empty file', async () => {
    await withTempFile('hello world', async (filePath) => {
      const result = await hashExecutable(filePath)
      expect(result).toMatch(/^[0-9a-f]{64}$/)
    })
  })

  it('produces the same hash when called twice on the same content', async () => {
    await withTempFile('consistent content', async (filePath) => {
      const first = await hashExecutable(filePath)
      const second = await hashExecutable(filePath)
      expect(first).toBe(second)
    })
  })

  it('produces different hashes for different file contents', async () => {
    await withTempFile('content A', async (fileA) => {
      const hashA = await hashExecutable(fileA)
      await withTempFile('content B', async (fileB) => {
        const hashB = await hashExecutable(fileB)
        expect(hashA).not.toBe(hashB)
      })
    })
  })

  it('produces a valid hash for an empty file', async () => {
    await withTempFile('', async (filePath) => {
      const result = await hashExecutable(filePath)
      // SHA-256 of empty input is well-known
      expect(result).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
    })
  })

  it('produces consistent hash for binary-like content', async () => {
    const binaryContent = Buffer.from([0x00, 0x01, 0x7f, 0xff, 0xfe]).toString('binary')
    await withTempFile(binaryContent, async (filePath) => {
      const first = await hashExecutable(filePath)
      const second = await hashExecutable(filePath)
      expect(first).toBe(second)
      expect(first).toMatch(/^[0-9a-f]{64}$/)
    })
  })

  it('rejects with an error for a non-existent file', async () => {
    await expect(hashExecutable('/does/not/exist/at/all.bin')).rejects.toThrow()
  })
})
