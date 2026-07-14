import * as crypto from 'node:crypto'
import * as fs from 'node:fs/promises'
import * as os from 'node:os'
import * as path from 'node:path'
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { approveCommand } from '../../../src/commands/approve.js'

/** Independent SHA-256 reference (the spec) — not the implementation under test. */
function sha256Hex(bytes: string): string {
  return crypto.createHash('sha256').update(bytes).digest('hex')
}

describe('approveCommand', () => {
  let stderrOutput: string
  let stdoutOutput: string
  let configDir: string
  const originalConfigDir = process.env.VAULTKEEPER_CONFIG_DIR

  beforeEach(async () => {
    stderrOutput = ''
    stdoutOutput = ''
    vi.spyOn(process.stderr, 'write').mockImplementation((chunk) => {
      stderrOutput += String(chunk)
      return true
    })
    vi.spyOn(process.stdout, 'write').mockImplementation((chunk) => {
      stdoutOutput += String(chunk)
      return true
    })
    // Isolate the trust manifest to a temp dir; never touch the real config dir.
    configDir = await fs.mkdtemp(path.join(os.tmpdir(), 'vk-approve-unit-'))
    process.env.VAULTKEEPER_CONFIG_DIR = configDir
  })

  afterEach(async () => {
    vi.restoreAllMocks()
    if (originalConfigDir === undefined) {
      delete process.env.VAULTKEEPER_CONFIG_DIR
    } else {
      process.env.VAULTKEEPER_CONFIG_DIR = originalConfigDir
    }
    await fs.rm(configDir, { recursive: true, force: true })
  })

  describe('--help / -h', () => {
    it('should print usage and return 0 for --help', async () => {
      const code = await approveCommand(['--help'])
      expect(code).toBe(0)
      expect(stdoutOutput).toContain('Usage: vaultkeeper approve')
    })

    it('should print usage and return 0 for -h', async () => {
      const code = await approveCommand(['-h'])
      expect(code).toBe(0)
      expect(stdoutOutput).toContain('Usage: vaultkeeper approve')
    })

    // Criterion 6: help describes the real (idempotent, manifest-writing) behavior.
    it('describes the TOFU manifest behavior accurately', async () => {
      await approveCommand(['--help'])
      expect(stdoutOutput).toContain('TOFU trust manifest')
      expect(stdoutOutput).toContain('idempotent')
    })
  })

  describe('--script flag validation', () => {
    it('should return 2 when --script is missing', async () => {
      const code = await approveCommand([])
      expect(code).toBe(2)
    })

    it('should write error to stderr when --script is missing', async () => {
      await approveCommand([])
      expect(stderrOutput).toContain('--script is required')
    })

    it('should include usage hint when --script is missing', async () => {
      await approveCommand([])
      expect(stderrOutput).toContain('Usage: vaultkeeper approve')
    })
  })

  describe('valid --script flag', () => {
    // Criterion 1: approve hashes the target and reports the recorded hash.
    it('records the hash and reports success', async () => {
      const contents = '#!/bin/sh\necho hi\n'
      const script = path.join(configDir, 'my-script.sh')
      await fs.writeFile(script, contents, { mode: 0o755 })

      const code = await approveCommand(['--script', script])
      expect(code).toBe(0)
      expect(stdoutOutput).toContain('Approved')
      expect(stdoutOutput).toContain(sha256Hex(contents))
    })

    it('resolves a relative script path to an absolute path in output', async () => {
      const contents = 'payload\n'
      const script = path.join(configDir, 'script.sh')
      await fs.writeFile(script, contents, { mode: 0o755 })

      const code = await approveCommand(['--script', script])
      expect(code).toBe(0)
      const match = /Approved (.+) \(hash:/.exec(stdoutOutput)
      const printedPath = match?.[1]
      expect(printedPath).toBeDefined()
      expect(path.isAbsolute(printedPath ?? '')).toBe(true)
    })
  })

  describe('missing script', () => {
    // Criterion 2: a nonexistent path exits non-zero, naming the missing path.
    it('exits 1 and names the missing path', async () => {
      const missing = path.join(configDir, 'does-not-exist.sh')
      const code = await approveCommand(['--script', missing])
      expect(code).toBe(1)
      expect(stderrOutput).toContain(path.resolve(missing))
    })
  })
})
