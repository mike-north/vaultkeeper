/**
 * CLI spawn wrapper for executing external commands.
 */

import { spawn, type ChildProcess } from 'node:child_process'
import { PluginNotFoundError, ExecError } from '../errors.js'
import { collectUtf8 } from './collect-utf8.js'

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
 * @throws {ExecError} if the command exits with a non-zero code, or if the
 *   process cannot be spawned for any reason other than the binary being
 *   missing (e.g. `EACCES`).
 * @throws {PluginNotFoundError} if the command binary is not found (`ENOENT`).
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
    let proc: ChildProcess
    try {
      proc = spawn(command, args, {
        stdio: [options?.stdin !== undefined ? 'pipe' : 'ignore', 'pipe', 'pipe'],
      })
    } catch {
      // Node can throw before emitting an error event, including for oversized argv.
      reject(new ExecError(`Failed to spawn '${command}'`, command))
      return
    }
    const stdout = collectUtf8(proc.stdout)
    const stderr = collectUtf8(proc.stderr)
    // A child can close the pipe before the write completes, even on exit zero.
    let stdinFailed = false
    // Undefined when no timeoutMs was given, or once the timer has fired.
    // Tracked so 'close'/'error' can clear it — otherwise an already-settled
    // promise still leaves the timer pending, which keeps the event loop
    // alive until it fires and calls proc.kill() on an already-exited
    // process (regression: PR #164 review, issue #127).
    let timeoutHandle: ReturnType<typeof setTimeout> | undefined

    if (options?.stdin !== undefined && proc.stdin) {
      proc.stdin.on('error', () => {
        stdinFailed = true
      })
      proc.stdin.end(options.stdin)
    }

    if (options?.timeoutMs !== undefined) {
      timeoutHandle = setTimeout(() => {
        // The timer has already fired, so there is nothing left to clear —
        // reset to undefined so the later 'close'/'error' handler's guard
        // matches reality instead of calling clearTimeout on a stale handle.
        timeoutHandle = undefined
        stdout.discard()
        stderr.discard()
        proc.kill('SIGTERM')
        reject(new ExecError(`Command timed out after ${String(options.timeoutMs)}ms`, command))
      }, options.timeoutMs)
    }

    proc.on('close', (code) => {
      if (timeoutHandle !== undefined) {
        clearTimeout(timeoutHandle)
      }
      // An explicit child failure carries the exit status and diagnostic output.
      if (stdinFailed && code === 0) {
        stdout.discard()
        stderr.discard()
        reject(new ExecError(`Failed to write stdin for '${command}'`, command))
        return
      }
      resolve({
        stdout: stdout.finish(),
        stderr: stderr.finish(),
        exitCode: code ?? 1,
      })
    })

    proc.on('error', (error) => {
      stdout.discard()
      stderr.discard()
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
        // Other asynchronous spawn failures use the same typed execution error.
        reject(new ExecError(`Failed to spawn '${command}': ${error.message}`, command))
      }
    })
  })
}
