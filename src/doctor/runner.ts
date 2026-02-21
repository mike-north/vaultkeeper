/**
 * Doctor runner: orchestrates platform-appropriate checks and aggregates results.
 *
 * @packageDocumentation
 */

import {
  checkOpenssl,
  checkBash,
  checkPowershell,
  checkSecurity,
  checkSecretTool,
  checkOp,
  checkYkman,
} from './checks.js'
import { currentPlatform } from '../util/platform.js'
import type { PreflightCheck, PreflightResult } from '../types.js'
import type { Platform } from '../util/platform.js'

/** Options for running the doctor. */
export interface RunDoctorOptions {
  /** Override the platform detection (useful for testing). */
  platform?: Platform
}

/** A doctor check entry pairing the check function with whether it is required. */
interface CheckEntry {
  check: () => Promise<PreflightCheck>
  required: boolean
}

/** Aggregated check entry with its result. */
interface ResolvedEntry {
  required: boolean
  result: PreflightCheck
}

/**
 * Run all platform-appropriate preflight checks and aggregate the results.
 */
export async function runDoctor(options?: RunDoctorOptions): Promise<PreflightResult> {
  const platform = options?.platform ?? currentPlatform()

  const entries: CheckEntry[] = buildCheckList(platform)

  const resolved: ResolvedEntry[] = await Promise.all(
    entries.map(async ({ check, required }) => {
      const result = await check()
      return { required, result }
    }),
  )

  const ready = resolved.every(({ required, result }) => {
    if (!required) return true
    return result.status === 'ok'
  })

  const warnings: string[] = []
  const nextSteps: string[] = []

  for (const { required, result } of resolved) {
    if (result.status === 'missing') {
      if (required) {
        nextSteps.push(`Install missing required dependency: ${result.name}`)
      } else {
        warnings.push(
          `Optional dependency not found: ${result.name}${result.reason !== undefined ? ` — ${result.reason}` : ''}`,
        )
      }
    } else if (result.status === 'version-unsupported') {
      const msg = `${result.name} version is unsupported${result.reason !== undefined ? `: ${result.reason}` : ''}`
      if (required) {
        nextSteps.push(`Upgrade required dependency: ${msg}`)
      } else {
        warnings.push(`Optional dependency version unsupported: ${msg}`)
      }
    }
  }

  const checks = resolved.map(({ result }) => result)

  return { checks, ready, warnings, nextSteps }
}

function buildCheckList(platform: Platform): CheckEntry[] {
  const entries: CheckEntry[] = [{ check: checkOpenssl, required: true }]

  if (platform === 'darwin') {
    entries.push({ check: checkSecurity, required: true })
    entries.push({ check: checkBash, required: false })
  } else if (platform === 'win32') {
    entries.push({ check: checkPowershell, required: true })
  } else {
    // linux
    entries.push({ check: checkBash, required: true })
    entries.push({ check: checkSecretTool, required: true })
  }

  // Optional tools on all platforms
  entries.push({ check: checkOp, required: false })
  entries.push({ check: checkYkman, required: false })

  return entries
}
