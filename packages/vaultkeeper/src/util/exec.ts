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
      setTimeout(() => {
        proc.kill('SIGTERM')
        reject(new ExecError(`Command timed out after ${String(options.timeoutMs)}ms`, command))
      }, options.timeoutMs)
    }

    proc.on('close', (code) => {
      resolve({ stdout, stderr, exitCode: code ?? 1 })
    })

    proc.on('error', (error) => {
      if ('code' in error && error.code === 'ENOENT') {
        reject(
          new PluginNotFoundError(
            `'${command}' is not installed or not found in PATH`,
            command,
            '',
          ),
        )
      } else {
        reject(error)
      }
    })
  })
}
