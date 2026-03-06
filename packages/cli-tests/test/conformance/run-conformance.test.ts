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

// ─── Types mirroring the Rust ConformanceCase / OutputMatcher ────

interface OutputMatcher {
  type: 'Any' | 'Exact' | 'Contains' | 'Regex' | 'JsonContains'
  value?: string | Record<string, unknown>
}

interface ConformanceCase {
  name: string
  command: string[]
  stdin: string | null
  needsConfig: boolean
  expectedExitCode: number
  expectedStdout: OutputMatcher
  expectedStderr: OutputMatcher
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

// ─── Output matching ─────────────────────────────────────────────

function matcherValueAsString(matcher: OutputMatcher): string {
  if (typeof matcher.value === 'string') return matcher.value
  return ''
}

function matchesOutput(matcher: OutputMatcher, output: string): boolean {
  switch (matcher.type) {
    case 'Any':
      return true
    case 'Exact':
      return output.trim() === matcherValueAsString(matcher).trim()
    case 'Contains':
      return output.includes(matcherValueAsString(matcher))
    case 'Regex': {
      let pattern = matcherValueAsString(matcher)
      let flags = ''
      // Translate Rust inline (?s) flag to JS 's' flag (dotall mode)
      if (pattern.startsWith('(?s)')) {
        pattern = pattern.slice(4)
        flags = 's'
      }
      return new RegExp(pattern, flags).test(output)
    }
    case 'JsonContains': {
      try {
        const parsed: unknown = JSON.parse(output)
        return jsonContains(parsed, matcher.value)
      } catch {
        return false
      }
    }
    default:
      return false
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function jsonContains(haystack: unknown, needle: unknown): boolean {
  if (isRecord(haystack) && isRecord(needle)) {
    return Object.entries(needle).every(
      ([k, v]) => k in haystack && jsonContains(haystack[k], v),
    )
  }
  if (Array.isArray(haystack) && Array.isArray(needle)) {
    return needle.every((nv: unknown) =>
      haystack.some((hv: unknown) => jsonContains(hv, nv)),
    )
  }
  return haystack === needle
}

// ─── Run a single case ───────────────────────────────────────────

interface RunResult {
  stdout: string
  stderr: string
  exitCode: number
}

async function runCase(testCase: ConformanceCase): Promise<RunResult> {
  const configDir = await fs.mkdtemp(
    path.join(os.tmpdir(), 'vk-conformance-'),
  )

  try {
    if (testCase.needsConfig) {
      await fs.writeFile(
        path.join(configDir, 'config.json'),
        DEFAULT_CONFIG + '\n',
        { mode: 0o600 },
      )
    }

    return await new Promise<RunResult>((resolve) => {
      const bin = RUST_BIN
      if (!bin) throw new Error('Rust binary not found')

      // Substitute __SELF_BINARY__ with the actual vaultkeeper binary path
      const args = testCase.command.map((arg) =>
        arg === '__SELF_BINARY__' ? bin : arg,
      )

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
            exitCode =
              typeof error.code === 'number' ? error.code : 1
          }
          resolve({ stdout, stderr, exitCode })
        },
      )

      if (child.stdin !== null) {
        // Ignore EPIPE — the child may exit before we finish writing
        // (e.g., clap rejecting args before reading stdin). This race
        // is more common on Node 20 than 22.
        child.stdin.on('error', () => {})
        if (testCase.stdin !== null) {
          child.stdin.write(testCase.stdin)
        }
        child.stdin.end()
      }
    })
  } finally {
    await fs.rm(configDir, { recursive: true, force: true })
  }
}

// ─── Test suite ──────────────────────────────────────────────────

// Skip the entire suite when the Rust binary isn't available (e.g., in CI
// where only the TypeScript packages are built).
describe.skipIf(RUST_BIN === null)('Rust CLI conformance', () => {
  it.each(cases.map((c): [string, ConformanceCase] => [c.name, c]))(
    '%s',
    async (_name, testCase) => {
      const result = await runCase(testCase)
      const errors: string[] = []

      // Check exit code (-1 means don't check)
      if (
        testCase.expectedExitCode !== -1 &&
        result.exitCode !== testCase.expectedExitCode
      ) {
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
