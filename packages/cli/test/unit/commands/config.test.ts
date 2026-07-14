import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import * as fs from 'node:fs/promises'
import * as os from 'node:os'
import * as path from 'node:path'

describe('configCommand', () => {
  let stderrOutput: string
  let stdoutOutput: string
  let tempDir: string
  let configDir: string

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
    // Create a fresh temp directory to isolate this test's config dir.
    // configCommand no longer derives a default path from os.homedir() —
    // it operates directly on whatever configDir is passed in.
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'vaultkeeper-config-test-'))
    configDir = path.join(tempDir, '.config', 'vaultkeeper')
  })

  afterEach(async () => {
    vi.restoreAllMocks()
    vi.clearAllMocks()
    await fs.rm(tempDir, { recursive: true, force: true })
  })

  describe('init subcommand', () => {
    it('should create config.json and return 0', async () => {
      const { configCommand } = await import('../../../src/commands/config.js')
      const code = await configCommand(['init'], configDir)
      expect(code).toBe(0)
    })

    it('should write success message to stdout', async () => {
      const { configCommand } = await import('../../../src/commands/config.js')
      await configCommand(['init'], configDir)
      expect(stdoutOutput).toContain('Config created at')
      expect(stdoutOutput).toContain('config.json')
    })

    it('should create config.json with valid JSON content', async () => {
      const { configCommand } = await import('../../../src/commands/config.js')
      await configCommand(['init'], configDir)
      const configPath = path.join(configDir, 'config.json')
      const content = await fs.readFile(configPath, 'utf8')
      const parsed: unknown = JSON.parse(content)
      expect(parsed).toMatchObject({ version: 1 })
    })

    it('should return 1 when config already exists', async () => {
      const { configCommand } = await import('../../../src/commands/config.js')
      await configCommand(['init'], configDir)
      const code = await configCommand(['init'], configDir)
      expect(code).toBe(1)
    })

    it('should write error to stderr when config already exists', async () => {
      const { configCommand } = await import('../../../src/commands/config.js')
      await configCommand(['init'], configDir)
      stderrOutput = ''
      await configCommand(['init'], configDir)
      expect(stderrOutput).toContain('Config already exists at')
    })
  })

  describe('show subcommand', () => {
    it('should output config content and return 0 when config exists', async () => {
      const { configCommand } = await import('../../../src/commands/config.js')
      await configCommand(['init'], configDir)
      stdoutOutput = ''
      const code = await configCommand(['show'], configDir)
      expect(code).toBe(0)
    })

    it('should write config content to stdout', async () => {
      const { configCommand } = await import('../../../src/commands/config.js')
      await configCommand(['init'], configDir)
      stdoutOutput = ''
      await configCommand(['show'], configDir)
      const parsed: unknown = JSON.parse(stdoutOutput)
      expect(parsed).toMatchObject({ version: 1 })
    })

    // No-config story (issue #68): commands that need config fall back to
    // platform defaults and say so — never an error, and never exit non-zero
    // — uniformly across store/delete/exec/config show/doctor. `config show`
    // previously erred with "No config file found" and exit 1; it now prints
    // the resolved default config and exits 0, matching the other commands.
    it('should return 0 and print platform defaults when config does not exist (regression: issue #68 uniform no-config story)', async () => {
      const { configCommand } = await import('../../../src/commands/config.js')
      const code = await configCommand(['show'], configDir)
      expect(code).toBe(0)
    })

    it('should write default config JSON to stdout when no config file exists', async () => {
      const { configCommand } = await import('../../../src/commands/config.js')
      await configCommand(['show'], configDir)
      const parsed: unknown = JSON.parse(stdoutOutput)
      expect(parsed).toMatchObject({ version: 1 })
    })

    it('should show a user-friendly "using platform defaults" message when no config file exists', async () => {
      const { configCommand } = await import('../../../src/commands/config.js')
      await configCommand(['show'], configDir)
      expect(stderrOutput).toContain('No config file found')
      expect(stderrOutput).toContain('using platform defaults')
      expect(stderrOutput).toContain('vaultkeeper config init')
    })

    it('should exit non-zero with a parse error, path, location, and remediation hint on invalid JSON (issue #68)', async () => {
      await fs.mkdir(configDir, { recursive: true })
      await fs.writeFile(path.join(configDir, 'config.json'), '{ bad json', 'utf8')
      const { configCommand } = await import('../../../src/commands/config.js')
      const code = await configCommand(['show'], configDir)
      expect(code).toBe(1)
      expect(stdoutOutput).toBe('')
      expect(stderrOutput).toContain(path.join(configDir, 'config.json'))
      expect(stderrOutput).toMatch(/line \d+, column \d+/)
      expect(stderrOutput).toContain('vaultkeeper config init')
    })

    it('never dumps invalid JSON with exit 0 (regression: issue #68 repro)', async () => {
      await fs.mkdir(configDir, { recursive: true })
      await fs.writeFile(path.join(configDir, 'config.json'), '{ bad json', 'utf8')
      const { configCommand } = await import('../../../src/commands/config.js')
      const code = await configCommand(['show'], configDir)
      expect(code).not.toBe(0)
      expect(stdoutOutput).not.toContain('bad json')
    })

    it('exits non-zero with a schema validation error, path, and remediation hint on structurally invalid config', async () => {
      await fs.mkdir(configDir, { recursive: true })
      await fs.writeFile(
        path.join(configDir, 'config.json'),
        JSON.stringify({ version: 99 }),
        'utf8',
      )
      const { configCommand } = await import('../../../src/commands/config.js')
      const code = await configCommand(['show'], configDir)
      expect(code).toBe(1)
      expect(stderrOutput).toContain(path.join(configDir, 'config.json'))
      expect(stderrOutput).toContain('version must be 1')
      expect(stderrOutput).toContain('vaultkeeper config init')
    })
  })

  describe('--help / -h', () => {
    it('should print usage and return 0 for --help', async () => {
      const { configCommand } = await import('../../../src/commands/config.js')
      const code = await configCommand(['--help'], configDir)
      expect(code).toBe(0)
      expect(stdoutOutput).toContain('Usage: vaultkeeper config')
    })

    it('should print usage and return 0 for -h', async () => {
      const { configCommand } = await import('../../../src/commands/config.js')
      const code = await configCommand(['-h'], configDir)
      expect(code).toBe(0)
      expect(stdoutOutput).toContain('Usage: vaultkeeper config')
    })
  })

  describe('missing/unknown subcommand', () => {
    it('should return 2 when no subcommand given', async () => {
      const { configCommand } = await import('../../../src/commands/config.js')
      const code = await configCommand([], configDir)
      expect(code).toBe(2)
    })

    it('should return 2 for unknown subcommand', async () => {
      const { configCommand } = await import('../../../src/commands/config.js')
      const code = await configCommand(['unknown'], configDir)
      expect(code).toBe(2)
    })

    it('should write usage to stderr for missing subcommand', async () => {
      const { configCommand } = await import('../../../src/commands/config.js')
      await configCommand([], configDir)
      expect(stderrOutput).toContain('Usage: vaultkeeper config')
    })
  })
})
