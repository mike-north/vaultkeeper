import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'

const configDir = '/tmp/vaultkeeper-test-config-dir'

// vi.hoisted ensures the mock factory can reference mockInit before imports are resolved.
const mockInit = vi.hoisted(() => vi.fn())
const mockStore = vi.hoisted(() => vi.fn().mockResolvedValue(undefined))
const mockGetTypes = vi.hoisted(() => vi.fn().mockReturnValue(['file']))
const mockCreate = vi.hoisted(() => vi.fn())

vi.mock('vaultkeeper', async (importOriginal) => {
  const { mockVaultkeeperModule } = await import('../../support/mock-vaultkeeper-module.js')
  return mockVaultkeeperModule(importOriginal, {
    VaultKeeper: {
      init: mockInit,
    },
    BackendRegistry: {
      getTypes: mockGetTypes,
      create: mockCreate,
    },
    defaultBackendType: vi.fn().mockReturnValue('file'),
  })
})

function mockStdinWith(value: string): void {
  vi.spyOn(process.stdin, Symbol.asyncIterator).mockImplementation(function* () {
    yield Buffer.from(value)
  })
}

describe('storeCommand', () => {
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
    mockGetTypes.mockReturnValue(['file'])
    mockStore.mockResolvedValue(undefined)
    mockCreate.mockReturnValue({ store: mockStore })
  })

  afterEach(() => {
    vi.restoreAllMocks()
    vi.clearAllMocks()
    delete process.env.VAULTKEEPER_SKIP_DOCTOR
  })

  describe('--name flag validation', () => {
    it('should return 2 when --name is missing', async () => {
      const { storeCommand } = await import('../../../src/commands/store.js')
      const code = await storeCommand([], configDir)
      expect(code).toBe(2)
    })

    it('should write error to stderr when --name is missing', async () => {
      const { storeCommand } = await import('../../../src/commands/store.js')
      await storeCommand([], configDir)
      expect(stderrOutput).toContain('--name is required')
    })

    it('should include usage hint when --name is missing', async () => {
      const { storeCommand } = await import('../../../src/commands/store.js')
      await storeCommand([], configDir)
      expect(stderrOutput).toContain('Usage:')
    })
  })

  describe('stdin validation', () => {
    // Regression: issue #118 — empty stdin previously returned exit 1 (a
    // runtime error), while an empty/missing --name returns 2 (a usage
    // error) for the exact same underlying problem: no usable secret input.
    // Both are equivalent misuse and must share the usage-error exit code.
    it('should return 2 when stdin is empty (issue #118 exit-code normalization)', async () => {
      mockStdinWith('')
      const { storeCommand } = await import('../../../src/commands/store.js')
      const code = await storeCommand(['--name', 'my-secret'], configDir)
      expect(code).toBe(2)
    })

    it('should write error and usage hint when stdin is empty', async () => {
      mockStdinWith('')
      const { storeCommand } = await import('../../../src/commands/store.js')
      await storeCommand(['--name', 'my-secret'], configDir)
      expect(stderrOutput).toContain('No secret provided on stdin')
      expect(stderrOutput).toContain('Usage:')
    })
  })

  describe('when VaultKeeper.init() throws', () => {
    it('should return 1', async () => {
      mockStdinWith('my-secret-value')
      mockInit.mockRejectedValue(new Error('backend unavailable'))
      const { storeCommand } = await import('../../../src/commands/store.js')
      const code = await storeCommand(['--name', 'my-secret'], configDir)
      expect(code).toBe(1)
    })

    it('should write formatted error to stderr', async () => {
      mockStdinWith('my-secret-value')
      mockInit.mockRejectedValue(new Error('backend unavailable'))
      const { storeCommand } = await import('../../../src/commands/store.js')
      await storeCommand(['--name', 'my-secret'], configDir)
      expect(stderrOutput).toContain('backend unavailable')
    })
  })

  describe('when store succeeds', () => {
    it('should return 0', async () => {
      mockStdinWith('my-secret-value')
      mockInit.mockResolvedValue({ store: mockStore })
      const { storeCommand } = await import('../../../src/commands/store.js')
      const code = await storeCommand(['--name', 'my-secret'], configDir)
      expect(code).toBe(0)
    })

    it('should write success message to stdout', async () => {
      mockStdinWith('my-secret-value')
      mockInit.mockResolvedValue({ store: mockStore })
      const { storeCommand } = await import('../../../src/commands/store.js')
      await storeCommand(['--name', 'my-secret'], configDir)
      expect(stdoutOutput).toContain('stored successfully')
    })
  })

  describe('--skip-doctor flag', () => {
    it('should pass skipDoctor: false to VaultKeeper.init by default', async () => {
      mockStdinWith('my-secret-value')
      mockInit.mockResolvedValue({ store: mockStore })
      const { storeCommand } = await import('../../../src/commands/store.js')
      await storeCommand(['--name', 'my-secret'], configDir)
      expect(mockInit).toHaveBeenCalledWith({ configDir, skipDoctor: false })
    })

    it('should pass skipDoctor: true to VaultKeeper.init when --skip-doctor is set', async () => {
      mockStdinWith('my-secret-value')
      mockInit.mockResolvedValue({ store: mockStore })
      const { storeCommand } = await import('../../../src/commands/store.js')
      await storeCommand(['--name', 'my-secret', '--skip-doctor'], configDir)
      expect(mockInit).toHaveBeenCalledWith({ configDir, skipDoctor: true })
    })

    it('should pass skipDoctor: true when VAULTKEEPER_SKIP_DOCTOR=1 env var is set', async () => {
      process.env.VAULTKEEPER_SKIP_DOCTOR = '1'
      mockStdinWith('my-secret-value')
      mockInit.mockResolvedValue({ store: mockStore })
      const { storeCommand } = await import('../../../src/commands/store.js')
      await storeCommand(['--name', 'my-secret'], configDir)
      expect(mockInit).toHaveBeenCalledWith({ configDir, skipDoctor: true })
    })

    it('should not skip doctor when VAULTKEEPER_SKIP_DOCTOR=0', async () => {
      process.env.VAULTKEEPER_SKIP_DOCTOR = '0'
      mockStdinWith('my-secret-value')
      mockInit.mockResolvedValue({ store: mockStore })
      const { storeCommand } = await import('../../../src/commands/store.js')
      await storeCommand(['--name', 'my-secret'], configDir)
      expect(mockInit).toHaveBeenCalledWith({ configDir, skipDoctor: false })
    })

    it('should not skip doctor when VAULTKEEPER_SKIP_DOCTOR=true (non-numeric)', async () => {
      process.env.VAULTKEEPER_SKIP_DOCTOR = 'true'
      mockStdinWith('my-secret-value')
      mockInit.mockResolvedValue({ store: mockStore })
      const { storeCommand } = await import('../../../src/commands/store.js')
      await storeCommand(['--name', 'my-secret'], configDir)
      expect(mockInit).toHaveBeenCalledWith({ configDir, skipDoctor: false })
    })

    it('should not skip doctor when VAULTKEEPER_SKIP_DOCTOR is empty string', async () => {
      process.env.VAULTKEEPER_SKIP_DOCTOR = ''
      mockStdinWith('my-secret-value')
      mockInit.mockResolvedValue({ store: mockStore })
      const { storeCommand } = await import('../../../src/commands/store.js')
      await storeCommand(['--name', 'my-secret'], configDir)
      expect(mockInit).toHaveBeenCalledWith({ configDir, skipDoctor: false })
    })
  })

  describe('--help flag', () => {
    it('should include --skip-doctor in help output', async () => {
      const { storeCommand } = await import('../../../src/commands/store.js')
      await storeCommand(['--help'], configDir)
      expect(stdoutOutput).toContain('--skip-doctor')
    })

    it('should include VAULTKEEPER_SKIP_DOCTOR env var in help output', async () => {
      const { storeCommand } = await import('../../../src/commands/store.js')
      await storeCommand(['--help'], configDir)
      expect(stdoutOutput).toContain('VAULTKEEPER_SKIP_DOCTOR')
    })
  })
})
