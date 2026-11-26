/**
 * Conformance test runner for the native Rust CLI.
 *
 * Loads data-driven test cases exported from `vaultkeeper-conformance` (Rust crate)
 * and runs each one against the compiled Rust binary. This ensures the native CLI
 * produces the exact same output as the Rust integration test runner.
 *
 * @see crates/vaultkeeper-conformance/src/lib.rs — case definitions
 * @see crates/vaultkeeper-conformance/tests/run_conformance.rs — Rust-side runner
 */

import { execFile } from 'node:child_process'
import * as fsSync from 'node:fs'
import * as fs from 'node:fs/promises'
import * as os from 'node:os'
import * as path from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, it, expect } from 'vitest'
import { matchesOutput, type OutputMatcher } from './matches-output.js'

// ─── Types mirroring the Rust ConformanceCase / OutputMatcher ────

interface ConformanceCase {
  name: string
  command: string[]
  stdin: string | null
  needsConfig: boolean
  expectedExitCode: number
  expectedStdout: OutputMatcher
  expectedStderr: OutputMatcher
  expectedConfigFile: OutputMatcher | null
  /** [path relative to the config dir, content] pairs, written before running. */
  extraFiles: [string, string][]
}

// ─── Load cases ──────────────────────────────────────────────────

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const casesPath = path.join(__dirname, 'cases.json')
// eslint-disable-next-line @typescript-eslint/no-unsafe-assignment -- JSON.parse returns any; validated by conformance crate
const cases: ConformanceCase[] = JSON.parse(await fs.readFile(casesPath, 'utf8'))

// ─── Find the native Rust CLI binary ─────────────────────────────

function findRustBinary(): string | null {
  // Check VAULTKEEPER_BIN env var first
  const envBin = process.env.VAULTKEEPER_BIN
  if (envBin) return envBin

  // Look in typical cargo target directories relative to workspace root
  const root = path.resolve(__dirname, '..', '..', '..', '..')
  const ext = process.platform === 'win32' ? '.exe' : ''
  const candidates = [
    path.join(root, 'target', 'debug', `vaultkeeper${ext}`),
    path.join(root, 'target', 'release', `vaultkeeper${ext}`),
  ]

  for (const candidate of candidates) {
    try {
      fsSync.accessSync(candidate)
      return candidate
    } catch {
      // try next
    }
  }

  return null
}

const RUST_BIN = findRustBinary()

// ─── Default test config ─────────────────────────────────────────

const DEFAULT_CONFIG = JSON.stringify(
  {
    version: 1,
    backends: [{ type: 'file', enabled: true }],
    keyRotation: { gracePeriodDays: 7 },
    defaults: { ttlMinutes: 60, trustTier: '3' },
  },
  null,
  2,
)

// ─── Fixture path validation ──────────────────────────────────────

/**
 * Reject any `extraFiles` path that is absolute or contains a
 * parent-directory (`..`) segment, so a malicious/malformed conformance case
 * can never write outside the case's isolated temp directory.
 */
function validateExtraFilePath(relPath: string): void {
  if (path.isAbsolute(relPath)) {
    throw new Error(`extraFiles path ${JSON.stringify(relPath)} must be relative, not absolute`)
  }
  // Mirrors the Rust runner's `Component::Normal`-only rule: every segment
  // must be a plain name, so '.', '..', and empty segments are all rejected.
  const segments = relPath.split(/[/\\]/)
  const isSafeRelative =
    segments.length > 0 && segments.every((s) => s !== '' && s !== '.' && s !== '..')
  if (!isSafeRelative) {
    throw new Error(
      `extraFiles path ${JSON.stringify(relPath)} must be relative and contain no '.', '..', or empty path segments`,
    )
  }
}

// ─── Run a single case ───────────────────────────────────────────

interface RunResult {
  stdout: string
  stderr: string
  exitCode: number
  /** Contents of config.json after the run, or null if it doesn't exist. */
  configFileContent: string | null
}

async function runCase(testCase: ConformanceCase): Promise<RunResult> {
  const configDir = await fs.mkdtemp(path.join(os.tmpdir(), 'vk-conformance-'))
  const configPath = path.join(configDir, 'config.json')

  try {
    if (testCase.needsConfig) {
      await fs.writeFile(configPath, DEFAULT_CONFIG + '\n', {
        mode: 0o600,
      })
    }

    for (const [relPath, content] of testCase.extraFiles) {
      validateExtraFilePath(relPath)
      const filePath = path.join(configDir, relPath)
      await fs.mkdir(path.dirname(filePath), { recursive: true })
      await fs.writeFile(filePath, content)
    }

    const { stdout, stderr, exitCode } = await new Promise<Omit<RunResult, 'configFileContent'>>(
      (resolve) => {
        const bin = RUST_BIN
        if (!bin) throw new Error('Rust binary not found')

        // Substitute __SELF_BINARY__ with the actual vaultkeeper binary path
        const args = testCase.command.map((arg) => (arg === '__SELF_BINARY__' ? bin : arg))

        const child = execFile(
          bin,
          args,
          {
            timeout: 15_000,
            env: {
              ...process.env,
              VAULTKEEPER_CONFIG_DIR: configDir,
            },
          },
          (error, stdout, stderr) => {
            let exitCode = 0
            if (error !== null) {
              // Node's ExecException puts the exit code in `code` as a number
              // when the process exits non-zero
              exitCode = typeof error.code === 'number' ? error.code : 1
            }
            resolve({ stdout, stderr, exitCode })
          },
        )

        if (child.stdin !== null) {
          // Ignore EPIPE — the child may exit before we finish writing
          // (e.g., clap rejecting args before reading stdin). This race
          // is more common on Node 20 than 22.
          // eslint-disable-next-line @typescript-eslint/no-empty-function -- suppress EPIPE from child exiting before stdin write completes
          child.stdin.on('error', () => {})
          if (testCase.stdin !== null) {
            child.stdin.write(testCase.stdin)
          }
          child.stdin.end()
        }
      },
    )

    let configFileContent: string | null = null
    if (testCase.expectedConfigFile !== null) {
      configFileContent = await fs.readFile(configPath, 'utf8').catch(() => null)
    }

    return { stdout, stderr, exitCode, configFileContent }
  } finally {
    await fs.rm(configDir, { recursive: true, force: true })
  }
}

// ─── Test suite ──────────────────────────────────────────────────

describe('validateExtraFilePath', () => {
  it('accepts a plain relative path', () => {
    expect(() => {
      validateExtraFilePath('profiles/empty-profile.json')
    }).not.toThrow()
  })

  it('rejects an absolute path', () => {
    expect(() => {
      validateExtraFilePath('/etc/passwd')
    }).toThrow(/must be relative/)
  })

  it('rejects a parent-directory traversal', () => {
    expect(() => {
      validateExtraFilePath('../../etc/passwd')
    }).toThrow(/\.\./)
  })

  it('rejects a parent-directory segment in the middle of the path', () => {
    expect(() => {
      validateExtraFilePath('profiles/../../escape.json')
    }).toThrow(/\.\./)
  })

  it('rejects an empty path', () => {
    expect(() => {
      validateExtraFilePath('')
    }).toThrow()
  })

  it("rejects a leading './' current-directory segment", () => {
    expect(() => {
      validateExtraFilePath('./profiles/x.json')
    }).toThrow(/'\.'/)
  })

  it("rejects a './' segment in the middle of the path", () => {
    expect(() => {
      validateExtraFilePath('a/./b')
    }).toThrow(/'\.'/)
  })

  it('rejects a doubled path separator (empty segment)', () => {
    expect(() => {
      validateExtraFilePath('a//b')
    }).toThrow(/empty/)
  })
})

// Skip the entire suite when the Rust binary isn't available (e.g., in CI
// where only the TypeScript packages are built).
describe.skipIf(RUST_BIN === null)('Rust CLI conformance', () => {
  it.each(cases.map((c): [string, ConformanceCase] => [c.name, c]))(
    '%s',
    async (_name, testCase) => {
      const result = await runCase(testCase)
      const errors: string[] = []

      // Check exit code (-1 means don't check)
      if (testCase.expectedExitCode !== -1 && result.exitCode !== testCase.expectedExitCode) {
        errors.push(
          `exit code: expected ${String(testCase.expectedExitCode)}, got ${String(result.exitCode)}`,
        )
      }

      if (!matchesOutput(testCase.expectedStdout, result.stdout)) {
        errors.push(
          `stdout mismatch: expected ${JSON.stringify(testCase.expectedStdout)}, got ${JSON.stringify(result.stdout.slice(0, 200))}`,
        )
      }

      if (!matchesOutput(testCase.expectedStderr, result.stderr)) {
        errors.push(
          `stderr mismatch: expected ${JSON.stringify(testCase.expectedStderr)}, got ${JSON.stringify(result.stderr.slice(0, 200))}`,
        )
      }

      if (testCase.expectedConfigFile !== null) {
        if (result.configFileContent === null) {
          errors.push('config file mismatch: expected config.json to exist, but it was not found')
        } else if (!matchesOutput(testCase.expectedConfigFile, result.configFileContent)) {
          errors.push(
            `config file mismatch: expected ${JSON.stringify(testCase.expectedConfigFile)}, got ${JSON.stringify(result.configFileContent.slice(0, 300))}`,
          )
        }
      }

      if (errors.length > 0) {
        const detail = [
          `stdout: ${JSON.stringify(result.stdout.slice(0, 300))}`,
          `stderr: ${JSON.stringify(result.stderr.slice(0, 300))}`,
          `exit: ${String(result.exitCode)}`,
        ].join('\n  ')

        expect.fail(`${errors.join('\n')}\n  ${detail}`)
      }
    },
  )
})
