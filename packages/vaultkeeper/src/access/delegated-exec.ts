/**
 * Delegated command execution access pattern.
 *
 * Replaces `{{secret}}` placeholders in command args and environment values,
 * then executes the command.
 */

import { spawn } from 'node:child_process'
import type { ExecRequest, ExecResult } from '../types.js'

const PLACEHOLDER = '{{secret}}'

function replacePlaceholder(value: string, secret: string): string {
  return value.replaceAll(PLACEHOLDER, secret)
}

function replaceInRecord(
  record: Record<string, string>,
  secret: string,
): Record<string, string> {
  const result: Record<string, string> = {}
  for (const [key, value] of Object.entries(record)) {
    result[key] = replacePlaceholder(value, secret)
  }
  return result
}

/**
 * Execute a delegated command with the secret injected into args and env.
 *
 * @param secret - The secret value to inject
 * @param request - The exec request template with `{{secret}}` placeholders
 * @returns The command result (stdout, stderr, exitCode)
 * @internal
 */
export function delegatedExec(
  secret: string,
  request: ExecRequest,
): Promise<ExecResult> {
  const args = (request.args ?? []).map((arg) => replacePlaceholder(arg, secret))
  const env =
    request.env !== undefined ? replaceInRecord(request.env, secret) : undefined

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
      reject(error)
    })
  })
}
