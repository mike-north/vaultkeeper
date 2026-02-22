import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import * as os from 'node:os'
import * as fs from 'node:fs/promises'
import * as path from 'node:path'

// Mock node:os so we can control homedir() per-test.
// vi.spyOn cannot patch ESM namespace exports at runtime.
vi.mock('node:os', async (importOriginal) => {
  const actual = await importOriginal<typeof os>()
  return {
    ...actual,
    homedir: vi.fn(() => actual.homedir()),
  }
})

describe('configCommand', () => {
  let stderrOutput: string
  let stdoutOutput: string
  let tempDir: string

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
    // Create a fresh temp directory and redirect homedir to it
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'vaultkeeper-config-test-'))
    vi.mocked(os.homedir).mockReturnValue(tempDir)
  })

  afterEach(async () => {
    vi.restoreAllMocks()
    vi.clearAllMocks()
    await fs.rm(tempDir, { recursive: true, force: true })
  })

  describe('init subcommand', () => {
    it('should create config.json and return 0', async () => {
      const { configCommand } = await import('../../../src/commands/config.js')
      const code = await configCommand(['init'])
      expect(code).toBe(0)
    })

    it('should write success message to stdout', async () => {
      const { configCommand } = await import('../../../src/commands/config.js')
      await configCommand(['init'])
      expect(stdoutOutput).toContain('Config created at')
      expect(stdoutOutput).toContain('config.json')
    })

    it('should create config.json with valid JSON content', async () => {
      const { configCommand } = await import('../../../src/commands/config.js')
      await configCommand(['init'])
      const configPath = path.join(tempDir, '.config', 'vaultkeeper', 'config.json')
      const content = await fs.readFile(configPath, 'utf8')
      const parsed: unknown = JSON.parse(content)
      expect(parsed).toMatchObject({ version: 1 })
    })

    it('should return 1 when config already exists', async () => {
      const { configCommand } = await import('../../../src/commands/config.js')
      await configCommand(['init'])
      const code = await configCommand(['init'])
      expect(code).toBe(1)
    })

    it('should write error to stderr when config already exists', async () => {
      const { configCommand } = await import('../../../src/commands/config.js')
      await configCommand(['init'])
      stderrOutput = ''
      await configCommand(['init'])
      expect(stderrOutput).toContain('Config already exists at')
    })
  })

  describe('show subcommand', () => {
    it('should output config content and return 0 when config exists', async () => {
      const { configCommand } = await import('../../../src/commands/config.js')
      await configCommand(['init'])
      stdoutOutput = ''
      const code = await configCommand(['show'])
      expect(code).toBe(0)
    })

    it('should write config content to stdout', async () => {
      const { configCommand } = await import('../../../src/commands/config.js')
      await configCommand(['init'])
      stdoutOutput = ''
      await configCommand(['show'])
      const parsed: unknown = JSON.parse(stdoutOutput)
      expect(parsed).toMatchObject({ version: 1 })
    })

    it('should return 1 when config does not exist', async () => {
      const { configCommand } = await import('../../../src/commands/config.js')
      const code = await configCommand(['show'])
      expect(code).toBe(1)
    })

    it('should write error to stderr when config does not exist', async () => {
      const { configCommand } = await import('../../../src/commands/config.js')
      await configCommand(['show'])
      expect(stderrOutput.length).toBeGreaterThan(0)
    })
  })

  describe('missing/unknown subcommand', () => {
    it('should return 1 when no subcommand given', async () => {
      const { configCommand } = await import('../../../src/commands/config.js')
      const code = await configCommand([])
      expect(code).toBe(1)
    })

    it('should return 1 for unknown subcommand', async () => {
      const { configCommand } = await import('../../../src/commands/config.js')
      const code = await configCommand(['unknown'])
      expect(code).toBe(1)
    })

    it('should write usage to stderr for missing subcommand', async () => {
      const { configCommand } = await import('../../../src/commands/config.js')
      await configCommand([])
      expect(stderrOutput).toContain('Usage: vaultkeeper config')
    })
  })
})
