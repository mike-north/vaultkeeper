/**
 * CLI spawn wrapper for executing external commands.
 */

import { spawn } from 'node:child_process'
import { PluginNotFoundError, ExecError } from '../errors.js'

/** Options for command execution. */
export interface ExecCommandOptions {
  /** Input to write to stdin */
  stdin?: string | undefined
  /** Timeout in milliseconds */
  timeoutMs?: number | undefined
}

/** Result of a command execution. */
export interface ExecCommandResult {
  stdout: string
  stderr: string
  exitCode: number
}

/**
 * Execute a command and return stdout.
 * @throws {ExecError} if the command exits with a non-zero code.
 */
export async function execCommand(
  command: string,
  args: string[],
  options?: ExecCommandOptions,
): Promise<string> {
  const result = await execCommandFull(command, args, options)
  if (result.exitCode !== 0) {
    throw new ExecError(
      `Command failed with exit code ${String(result.exitCode)}: ${result.stderr}`,
      command,
    )
  }
  return result.stdout.trim()
}

/**
 * Execute a command and return the full result.
 */
export function execCommandFull(
  command: string,
  args: string[],
  options?: ExecCommandOptions,
): Promise<ExecCommandResult> {
  return new Promise((resolve, reject) => {
    const proc = spawn(command, args, {
      stdio: [options?.stdin !== undefined ? 'pipe' : 'ignore', 'pipe', 'pipe'],
    })
    let stdout = ''
    let stderr = ''
    // Undefined when no timeoutMs was given, or once the timer has fired.
    // Tracked so 'close'/'error' can clear it — otherwise an already-settled
    // promise still leaves the timer pending, which keeps the event loop
    // alive until it fires and calls proc.kill() on an already-exited
    // process (regression: PR #164 review, issue #127).
    let timeoutHandle: ReturnType<typeof setTimeout> | undefined

    proc.stdout?.on('data', (data: Buffer) => {
      stdout += data.toString()
    })

    proc.stderr?.on('data', (data: Buffer) => {
      stderr += data.toString()
    })

    if (options?.stdin !== undefined && proc.stdin) {
      proc.stdin.write(options.stdin)
      proc.stdin.end()
    }

    if (options?.timeoutMs !== undefined) {
      timeoutHandle = setTimeout(() => {
        // The timer has already fired, so there is nothing left to clear —
        // reset to undefined so the later 'close'/'error' handler's guard
        // matches reality instead of calling clearTimeout on a stale handle.
        timeoutHandle = undefined
        proc.kill('SIGTERM')
        reject(new ExecError(`Command timed out after ${String(options.timeoutMs)}ms`, command))
      }, options.timeoutMs)
    }

    proc.on('close', (code) => {
      if (timeoutHandle !== undefined) {
        clearTimeout(timeoutHandle)
      }
      resolve({ stdout, stderr, exitCode: code ?? 1 })
    })

    proc.on('error', (error) => {
      if (timeoutHandle !== undefined) {
        clearTimeout(timeoutHandle)
      }
      if ('code' in error && error.code === 'ENOENT') {
        reject(
          new PluginNotFoundError(
            `'${command}' is not installed or not found in PATH`,
            command,
            '',
          ),
        )
      } else {
        // Any other spawn failure (EACCES on the binary, EMFILE, ...) must
        // surface typed, not as the raw Node error — the last plain-error
        // escape on this utility's failure paths.
        reject(new ExecError(`Failed to spawn '${command}': ${error.message}`, command))
      }
    })
  })
}
