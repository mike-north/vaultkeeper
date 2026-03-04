/**
 * Factory for isolated CLI test environments.
 * @public
 */

import * as fs from 'node:fs/promises'
import * as os from 'node:os'
import * as path from 'node:path'
import { execFile } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import type { CliTestEnv, CliTestEnvOptions, CliResult } from './types.js'

const __dirname = path.dirname(fileURLToPath(import.meta.url))

/**
 * Resolve the path to the CLI bin.ts entry point.
 * cli-test-helpers lives at packages/cli-test-helpers/src/ (or dist/).
 * The CLI lives at packages/cli/src/bin.ts.
 */
function resolveCliBinPath(): string {
  // From src/ or dist/, go up to packages/cli-test-helpers, then to packages/cli/src/bin.ts
  return path.resolve(__dirname, '..', '..', 'cli', 'src', 'bin.ts')
}

/**
 * Resolve the tsx binary for spawning TypeScript files directly.
 * Uses PATH lookup so the correct platform-specific shim is found.
 */
function resolveTsxBin(): string {
  return 'tsx'
}

const DEFAULT_CONFIG = {
  version: 1,
  backends: [{ type: 'file', enabled: true }],
  keyRotation: { gracePeriodDays: 7 },
  defaults: { ttlMinutes: 60, trustTier: 3 },
}

function runProcess(
  tsxBin: string,
  binPath: string,
  args: string[],
  env: Record<string, string | undefined>,
  timeout: number,
  stdinData?: string,
): Promise<CliResult> {
  return new Promise((resolve) => {
    const child = execFile(
      tsxBin,
      [binPath, ...args],
      { timeout, env },
      (error, stdout, stderr) => {
        const exitCode =
          error !== null
            ? typeof error.code === 'number'
              ? error.code
              : 1
            : 0
        resolve({ stdout, stderr, exitCode })
      },
    )

    if (stdinData !== undefined && child.stdin !== null) {
      child.stdin.write(stdinData)
      child.stdin.end()
    } else if (child.stdin !== null) {
      // Close stdin so commands that read from it don't hang
      child.stdin.end()
    }
  })
}

/**
 * Create an isolated CLI test environment.
 *
 * @param options - Optional configuration for the test environment.
 * @returns A disposable test environment with `run()`, `runWithStdin()`, and `cleanup()`.
 * @public
 */
export async function createCliTestEnv(
  options?: CliTestEnvOptions,
): Promise<CliTestEnv> {
  const configDir = await fs.mkdtemp(
    path.join(os.tmpdir(), 'vaultkeeper-cli-test-'),
  )

  const secretsDir = path.join(configDir, 'secrets')
  await fs.mkdir(secretsDir, { recursive: true })

  const configContent = options?.config ?? DEFAULT_CONFIG
  await fs.writeFile(
    path.join(configDir, 'config.json'),
    JSON.stringify(configContent, null, 2) + '\n',
    { encoding: 'utf8', mode: 0o600 },
  )

  const tsxBin = resolveTsxBin()
  const binPath = resolveCliBinPath()
  const timeout = options?.timeout ?? 15_000
  const extraEnv = options?.env ?? {}

  const baseEnv: Record<string, string | undefined> = {
    ...process.env,
    ...extraEnv,
    VAULTKEEPER_CONFIG_DIR: configDir,
  }

  return {
    configDir,

    run(args: string[]): Promise<CliResult> {
      return runProcess(tsxBin, binPath, args, baseEnv, timeout)
    },

    runWithStdin(args: string[], stdin: string): Promise<CliResult> {
      return runProcess(tsxBin, binPath, args, baseEnv, timeout, stdin)
    },

    async cleanup(): Promise<void> {
      await fs.rm(configDir, { recursive: true, force: true })
    },
  }
}
