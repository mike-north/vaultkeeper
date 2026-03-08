/**
 * Doctor runner: orchestrates platform-appropriate checks and aggregates results.
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
import type { BackendConfig, PreflightCheck, PreflightResult } from '../types.js'
import type { Platform } from '../util/platform.js'

/**
 * Options for running the doctor.
 * @public
 */
export interface RunDoctorOptions {
  /** Override the platform detection (useful for testing). */
  platform?: Platform
  /**
   * When provided, doctor checks are scoped to the given backends.
   * Checks for system dependencies that are only needed by backends not in
   * this list are demoted from required to optional (still run for
   * informational purposes, but will not block readiness).
   *
   * When omitted, all platform-default checks are treated as required
   * (backward-compatible behavior).
   */
  backends?: BackendConfig[]
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
 * @public
 */
export async function runDoctor(options?: RunDoctorOptions): Promise<PreflightResult> {
  let platform: Platform
  try {
    platform = options?.platform ?? currentPlatform()
  } catch {
    return {
      checks: [],
      ready: false,
      warnings: [],
      nextSteps: ['Unsupported platform. vaultkeeper supports macOS, Linux, and Windows.'],
    }
  }

  const enabledTypes = enabledBackendTypes(options?.backends)
  const entries: CheckEntry[] = buildCheckList(platform, enabledTypes)

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

/**
 * Extract the set of enabled backend type strings from the config.
 * Returns `null` when no backend list was provided, signalling that the
 * caller should fall back to platform defaults (backward-compatible).
 */
function enabledBackendTypes(
  backends: BackendConfig[] | undefined,
): Set<string> | null {
  if (backends === undefined) return null
  const types = new Set<string>()
  for (const b of backends) {
    if (b.enabled) types.add(b.type)
  }
  return types
}

function buildCheckList(
  platform: Platform,
  enabledTypes: Set<string> | null,
): CheckEntry[] {
  // Core checks are always required regardless of backends.
  const entries: CheckEntry[] = [{ check: checkOpenssl, required: true }]

  if (platform === 'darwin') {
    // `security` is required only if keychain backend is configured (or no
    // backend list was provided, preserving backward-compatible defaults).
    entries.push({
      check: checkSecurity,
      required: enabledTypes === null || enabledTypes.has('keychain'),
    })
    entries.push({ check: checkBash, required: false })
  } else if (platform === 'win32') {
    entries.push({
      check: checkPowershell,
      required: enabledTypes === null || enabledTypes.has('dpapi'),
    })
  } else {
    // linux
    entries.push({ check: checkBash, required: true })
    entries.push({
      check: checkSecretTool,
      required: enabledTypes === null || enabledTypes.has('secret-tool'),
    })
  }

  // Plugin backend tools — required only if the corresponding backend is
  // explicitly enabled; otherwise optional (informational).
  entries.push({
    check: checkOp,
    required: enabledTypes?.has('1password') ?? false,
  })
  entries.push({
    check: checkYkman,
    required: enabledTypes?.has('yubikey') ?? false,
  })

  return entries
}
