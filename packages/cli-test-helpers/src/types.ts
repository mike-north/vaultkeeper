/**
 * Result from running the CLI binary as a subprocess.
 * @public
 */
export interface CliResult {
  /** Standard output captured from the process. */
  stdout: string
  /** Standard error captured from the process. */
  stderr: string
  /** Process exit code. */
  exitCode: number
}

/**
 * Options for configuring a CLI test environment.
 * @public
 */
export interface CliTestEnvOptions {
  /** Override config.json contents. If omitted, writes a file-backend config. */
  config?: Record<string, unknown>
  /** Extra environment variables for the subprocess. */
  env?: Record<string, string>
  /** Subprocess timeout in ms (default: 15000). */
  timeout?: number
  /**
   * How the isolated config directory is communicated to the CLI subprocess.
   *
   * - `'env'` (default): sets `VAULTKEEPER_CONFIG_DIR` in the subprocess env.
   * - `'flag'`: does not set `VAULTKEEPER_CONFIG_DIR` — tests must pass
   *   `--config-dir <env.configDir>` explicitly via `run()`/`runWithStdin()`
   *   args. Use this to exercise `--config-dir` flag behavior in isolation,
   *   including precedence over a separately-set env var.
   */
  configDirMode?: 'env' | 'flag'
}

/**
 * A disposable CLI test environment with an isolated config dir and file backend.
 * @public
 */
export interface CliTestEnv {
  /** The isolated temporary config directory. */
  configDir: string
  /** Run the vaultkeeper CLI with the given args. */
  run(args: string[]): Promise<CliResult>
  /** Run the CLI with data piped to stdin. */
  runWithStdin(args: string[], stdin: string): Promise<CliResult>
  /** Clean up the temp directory. */
  cleanup(): Promise<void>
}
