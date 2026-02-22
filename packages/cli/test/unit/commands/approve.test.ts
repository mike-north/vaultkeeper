import * as path from 'node:path'
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { approveCommand } from '../../../src/commands/approve.js'

describe('approveCommand', () => {
  let stderrOutput: string
  let stdoutOutput: string

  beforeEach(() => {
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
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  describe('--script flag validation', () => {
    it('should return 1 when --script is missing', () => {
      const code = approveCommand([])
      expect(code).toBe(1)
    })

    it('should write error to stderr when --script is missing', () => {
      approveCommand([])
      expect(stderrOutput).toContain('--script is required')
    })

    it('should include usage hint when --script is missing', () => {
      approveCommand([])
      expect(stderrOutput).toContain('Usage: vaultkeeper approve')
    })
  })

  describe('valid --script flag', () => {
    it('should return 0 when --script is provided', () => {
      const code = approveCommand(['--script', '/path/to/my-script.sh'])
      expect(code).toBe(0)
    })

    it('should write success message to stdout', () => {
      approveCommand(['--script', '/path/to/my-script.sh'])
      expect(stdoutOutput).toContain('Script approved:')
    })

    it('should write first-use note to stdout', () => {
      approveCommand(['--script', '/path/to/my-script.sh'])
      expect(stdoutOutput).toContain('first use')
    })

    it('should resolve the script path before printing', () => {
      approveCommand(['--script', 'relative/script.sh'])
      // resolving makes it absolute — must contain an absolute-path indicator
      expect(stdoutOutput).toContain('script.sh')
      // The printed path should be absolute (starts with /)
      const match = /Script approved: (.+)\n/.exec(stdoutOutput)
      const printedPath = match?.[1]
      expect(printedPath).toBeDefined()
      expect(path.isAbsolute(printedPath ?? '')).toBe(true)
    })
  })
})
