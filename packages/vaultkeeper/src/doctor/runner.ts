/**
 * Doctor runner: orchestrates platform-appropriate checks and aggregates results.
 */

import * as path from 'node:path'
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
import { loadConfig } from '../config.js'
import type {
  BackendConfig,
  PreflightCheck,
  PreflightResult,
  ScopedPreflightCheck,
} from '../types.js'
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
   * Platform-native dependency checks (e.g. `secret-tool`, `security`,
   * `powershell`) are demoted from required to optional when the
   * corresponding backend is not enabled. Plugin tool checks (`op`,
   * `ykman`) are promoted from optional to required when their backend
   * (`1password`, `yubikey`) is explicitly enabled.
   *
   * When omitted, all platform-default checks are treated as required
   * (backward-compatible behavior).
   */
  backends?: BackendConfig[]
  /**
   * When provided (and `backends` is not explicitly given), doctor loads and
   * validates the config file under this directory, adding a `config`
   * preflight check to the result. A present-but-invalid config file (parse
   * or schema failure) becomes a failing, required check — with the
   * underlying error's message (file path, parse location, remediation hint)
   * as `reason` — so an invalid config is visible in `doctor`'s output and
   * fails the overall `ready` result (issue #68). A missing config file is
   * not an error: `loadConfig` resolves platform defaults and the check
   * reports `ok`.
   */
  configDir?: string
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

  // Resolve the config check and backend list together: an explicit
  // `backends` option always wins (backward-compatible, and used by callers
  // that already loaded/validated the config themselves, e.g. VaultKeeper.init
  // after a successful loadConfig). Otherwise, when `configDir` is given,
  // doctor loads and validates the config itself so an invalid config file
  // surfaces as a failing check instead of being invisible to doctor.
  let backends = options?.backends
  let configCheck: ScopedPreflightCheck | undefined
  if (backends === undefined && options?.configDir !== undefined) {
    const configPath = path.join(options.configDir, 'config.json')
    try {
      const config = await loadConfig(options.configDir)
      backends = config.backends
      configCheck = { name: 'config', status: 'ok', version: configPath, required: true }
    } catch (err) {
      configCheck = {
        name: 'config',
        status: 'invalid',
        reason: err instanceof Error ? err.message : String(err),
        required: true,
      }
    }
  }

  const enabledTypes = enabledBackendTypes(backends)
  const entries: CheckEntry[] = buildCheckList(platform, enabledTypes)

  const resolved: ResolvedEntry[] = await Promise.all(
    entries.map(async ({ check, required }) => {
      const result = await check()
      return { required, result }
    }),
  )

  const configReady = configCheck === undefined || configCheck.status === 'ok'
  const ready =
    configReady &&
    resolved.every(({ required, result }) => {
      if (!required) return true
      return result.status === 'ok'
    })

  const warnings: string[] = []
  const nextSteps: string[] = []

  if (configCheck !== undefined && configCheck.status !== 'ok') {
    // The config check is always required — an invalid config means the
    // vault cannot operate, so it always contributes a nextStep, never a
    // mere warning.
    nextSteps.push(configCheck.reason ?? 'Config file is invalid.')
  }

  for (const { required, result } of resolved) {
    const reasonSuffix = result.reason !== undefined ? ` — ${result.reason}` : ''

    if (result.status === 'missing') {
      if (required) {
        nextSteps.push(`Install missing required dependency: ${result.name}${reasonSuffix}`)
      } else {
        warnings.push(`Optional dependency not found: ${result.name}${reasonSuffix}`)
      }
    } else if (result.status === 'version-unsupported') {
      const msg = `${result.name} version is unsupported${reasonSuffix}`
      if (required) {
        nextSteps.push(`Upgrade required dependency: ${msg}`)
      } else {
        warnings.push(`Optional dependency version unsupported: ${msg}`)
      }
    }
  }

  const checks: ScopedPreflightCheck[] = [
    ...(configCheck !== undefined ? [configCheck] : []),
    ...resolved.map(({ required, result }) => ({ ...result, required })),
  ]

  return { checks, ready, warnings, nextSteps }
}

/**
 * Extract the set of enabled backend type strings from the config.
 * Returns `null` when no backend list was provided, signalling that the
 * caller should fall back to platform defaults (backward-compatible).
 */
function enabledBackendTypes(backends: BackendConfig[] | undefined): Set<string> | null {
  if (backends === undefined) return null
  const types = new Set<string>()
  for (const b of backends) {
    if (b.enabled) types.add(b.type)
  }
  return types
}

function buildCheckList(platform: Platform, enabledTypes: Set<string> | null): CheckEntry[] {
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
