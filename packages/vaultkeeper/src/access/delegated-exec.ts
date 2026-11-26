/**
 * Delegated command execution access pattern.
 *
 * Replaces `{{secret}}` or `{{secret:name}}` placeholders in environment
 * values, then executes the command. Placeholders are rejected in the
 * `command` and `args` fields — process arguments (and the command name)
 * are visible to other processes via `ps` and often collected in logs and
 * telemetry, so secrets must be injected via `env` instead.
 *
 * By default the captured `stdout`/`stderr` is scrubbed of every injected
 * secret value (replaced with `[REDACTED]`) before it is returned, so a
 * command that echoes the secret never leaks it back through the return value.
 * `request.redact === false` opts out and returns raw output.
 */

import { spawn } from 'node:child_process'
import { collectUtf8 } from '../util/collect-utf8.js'
import type { ExecRequest, ExecResult } from '../types.js'
import { ExecError, VaultError } from '../errors.js'
import { ANY_PLACEHOLDER_RE, resolvePlaceholdersInRecord } from './placeholder.js'
import { redactSecrets } from './redact.js'

/**
 * Execute a delegated command with secrets injected into env.
 *
 * @param secrets - A single secret string (replaces `{{secret}}`) or a
 *   name-to-value map (replaces `{{secret:name}}`)
 * @param request - The exec request template with placeholders. Placeholders
 *   are only resolved in `env`; `command` and `args` reject them with
 *   `ExecError`.
 * @returns The command result (stdout, stderr, exitCode)
 * @internal
 */
export async function delegatedExec(
  secrets: string | Record<string, string>,
  request: ExecRequest,
): Promise<ExecResult> {
  if (ANY_PLACEHOLDER_RE.test(request.command)) {
    throw new ExecError(
      `Secret placeholders are not supported in the command field. Use env instead.`,
      request.command,
    )
  }

  const args = request.args ?? []
  for (const arg of args) {
    if (ANY_PLACEHOLDER_RE.test(arg)) {
      throw new ExecError(
        `Secret placeholders are not supported in the args field — process arguments are visible to other processes via ps. Use env instead.`,
        request.command,
      )
    }
  }

  // Every value that could have been injected into the child's environment.
  // These are what we scrub from captured output so an echoed secret never
  // leaks back through stdout/stderr. Redacting values that were not actually
  // injected is harmless (they simply won't be present) and keeps the set
  // conservative.
  const secretValues = typeof secrets === 'string' ? [secrets] : Object.values(secrets)
  const shouldRedact = request.redact !== false

  let env: Record<string, string> | undefined
  try {
    env = request.env !== undefined ? resolvePlaceholdersInRecord(request.env, secrets) : undefined
  } catch (error) {
    if (error instanceof VaultError) {
      throw new ExecError(error.message, request.command)
    }
    throw error
  }

  return new Promise((resolve, reject) => {
    const spawnOptions: Parameters<typeof spawn>[2] = {
      stdio: ['ignore', 'pipe', 'pipe'],
    }
    if (env !== undefined) {
      spawnOptions.env = { ...process.env, ...env }
    }
    if (request.cwd !== undefined) {
      spawnOptions.cwd = request.cwd
    }

    const proc = spawn(request.command, args, spawnOptions)
    const stdout = collectUtf8(proc.stdout)
    const stderr = collectUtf8(proc.stderr)

    proc.on('close', (code) => {
      const stdoutText = stdout.finish()
      const stderrText = stderr.finish()
      resolve({
        stdout: shouldRedact ? redactSecrets(stdoutText, secretValues) : stdoutText,
        stderr: shouldRedact ? redactSecrets(stderrText, secretValues) : stderrText,
        exitCode: code ?? 1,
      })
    })

    proc.on('error', (error) => {
      stdout.discard()
      stderr.discard()
      const isEnoent = error instanceof Error && 'code' in error && error.code === 'ENOENT'
      if (isEnoent) {
        reject(
          new ExecError(
            `Command not found: ${request.command}. Verify the command exists and is in PATH.`,
            request.command,
          ),
        )
      } else {
        reject(
          new ExecError(
            `Failed to execute command: ${request.command}. ${error instanceof Error ? error.message : String(error)}`,
            request.command,
          ),
        )
      }
    })
  })
}
