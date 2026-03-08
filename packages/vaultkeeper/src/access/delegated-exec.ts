/**
 * Delegated command execution access pattern.
 *
 * Replaces `{{secret}}` or `{{secret:name}}` placeholders in command args
 * and environment values, then executes the command.
 */

import { spawn } from 'node:child_process'
import type { ExecRequest, ExecResult } from '../types.js'
import { ExecError } from '../errors.js'
import {
  ANY_PLACEHOLDER_RE,
  resolvePlaceholders,
  resolvePlaceholdersInRecord,
} from './placeholder.js'

/**
 * Execute a delegated command with secrets injected into args and env.
 *
 * @param secrets - A single secret string (replaces `{{secret}}`) or a
 *   name-to-value map (replaces `{{secret:name}}`)
 * @param request - The exec request template with placeholders
 * @returns The command result (stdout, stderr, exitCode)
 * @internal
 */
export function delegatedExec(
  secrets: string | Record<string, string>,
  request: ExecRequest,
): Promise<ExecResult> {
  if (ANY_PLACEHOLDER_RE.test(request.command)) {
    throw new ExecError(
      `Secret placeholders are not supported in the command field. Use args or env instead.`,
      request.command,
    )
  }

  const args = (request.args ?? []).map((arg) =>
    resolvePlaceholders(arg, secrets),
  )
  const env =
    request.env !== undefined
      ? resolvePlaceholdersInRecord(request.env, secrets)
      : undefined

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
    let stdout = ''
    let stderr = ''

    proc.stdout?.on('data', (data: Buffer) => {
      stdout += data.toString()
    })

    proc.stderr?.on('data', (data: Buffer) => {
      stderr += data.toString()
    })

    proc.on('close', (code) => {
      resolve({ stdout, stderr, exitCode: code ?? 1 })
    })

    proc.on('error', (error) => {
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
