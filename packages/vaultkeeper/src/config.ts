/**
 * Configuration loading, validation, and defaults for vaultkeeper.
 */

import * as fs from 'node:fs/promises'
import * as path from 'node:path'
import * as os from 'node:os'
import type { VaultConfig, BackendConfig, TrustTier } from './types.js'
import { ConfigValidationError } from './errors.js'

/**
 * Return the platform-appropriate default config directory.
 *
 * Resolution order: the `VAULTKEEPER_CONFIG_DIR` environment variable, then
 * the platform default (`%APPDATA%/vaultkeeper` on Windows,
 * `~/.config/vaultkeeper` elsewhere). Consumers that also support a
 * higher-precedence override (e.g. a CLI flag) should check that first and
 * only fall back to this function when no override was supplied.
 *
 * @public
 */
export function getDefaultConfigDir(): string {
  const envOverride = process.env.VAULTKEEPER_CONFIG_DIR
  if (envOverride !== undefined && envOverride !== '') {
    return envOverride
  }
  if (process.platform === 'win32') {
    const appData = process.env.APPDATA
    if (appData !== undefined) {
      return path.join(appData, 'vaultkeeper')
    }
    return path.join(os.homedir(), 'AppData', 'Roaming', 'vaultkeeper')
  }
  return path.join(os.homedir(), '.config', 'vaultkeeper')
}

/**
 * Resolve the backend type that vaultkeeper uses by default on the current
 * platform when no backend is explicitly configured.
 *
 * @remarks
 * The default deliberately targets the platform-native OS credential store so
 * that secrets are protected by the operating system out of the box:
 *
 * - **macOS** → `keychain` (macOS Keychain)
 * - **Windows** → `dpapi` (Windows DPAPI)
 * - **all other platforms** (Linux, etc.) → `file` (AES-256-GCM encrypted file)
 *
 * On macOS and Windows this means a bare {@link VaultKeeper.init} — or a
 * `vaultkeeper config init` with no `--backend` flag — writes to the real OS
 * credential store. Choose `file` explicitly for a portable, CI-friendly store
 * that requires no system credential service.
 *
 * @returns The default backend type identifier for the current platform.
 * @public
 */
export function platformDefaultBackendType(): string {
  if (process.platform === 'darwin') {
    return 'keychain'
  }
  if (process.platform === 'win32') {
    return 'dpapi'
  }
  // Linux and other Unix-like systems. Use 'file' rather than 'secret-tool'
  // because secret-tool requires libsecret-tools, which many systems lack.
  return 'file'
}

/**
 * Default configuration when no config file exists.
 *
 * The active backend is resolved by {@link platformDefaultBackendType}.
 */
function defaultConfig(): VaultConfig {
  return {
    version: 1,
    backends: [{ type: platformDefaultBackendType(), enabled: true }],
    keyRotation: { gracePeriodDays: 7 },
    defaults: { ttlMinutes: 60, trustTier: 3 },
  }
}

/**
 * Type guard for plain objects.
 */
function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

/**
 * Validates a backend config entry.
 */
function validateBackendEntry(entry: unknown, index: number): BackendConfig {
  const base = `backends[${String(index)}]`

  if (!isObject(entry)) {
    throw new ConfigValidationError(`${base} must be an object`, base)
  }
  if (typeof entry.type !== 'string' || entry.type.trim() === '') {
    throw new ConfigValidationError(`${base}.type must be a non-empty string`, `${base}.type`)
  }
  if (typeof entry.enabled !== 'boolean') {
    throw new ConfigValidationError(`${base}.enabled must be a boolean`, `${base}.enabled`)
  }

  const result: BackendConfig = {
    type: entry.type,
    enabled: entry.enabled,
  }

  if (entry.plugin !== undefined) {
    if (typeof entry.plugin !== 'boolean') {
      throw new ConfigValidationError(`${base}.plugin must be a boolean`, `${base}.plugin`)
    }
    result.plugin = entry.plugin
  }

  if (entry.path !== undefined) {
    if (typeof entry.path !== 'string') {
      throw new ConfigValidationError(`${base}.path must be a string`, `${base}.path`)
    }
    if (entry.path.trim() === '') {
      throw new ConfigValidationError(
        `${base}.path must not be empty or whitespace-only`,
        `${base}.path`,
      )
    }
    result.path = entry.path
  }

  if (entry.options !== undefined) {
    if (!isObject(entry.options)) {
      throw new ConfigValidationError(`${base}.options must be an object`, `${base}.options`)
    }
    const opts: Record<string, string> = {}
    for (const [k, v] of Object.entries(entry.options)) {
      if (typeof v !== 'string') {
        const quotedKey = JSON.stringify(k)
        throw new ConfigValidationError(
          `${base}.options[${quotedKey}] must be a string`,
          `${base}.options[${quotedKey}]`,
        )
      }
      opts[k] = v
    }
    result.options = opts
  }

  return result
}

/**
 * Validate an unknown value as a VaultConfig, throwing on invalid structure.
 * @internal
 */
export function validateConfig(config: unknown): VaultConfig {
  if (!isObject(config)) {
    throw new ConfigValidationError('Config must be an object', 'config')
  }

  if (typeof config.version !== 'number' || config.version !== 1) {
    throw new ConfigValidationError('Config version must be 1', 'version')
  }

  if (!Array.isArray(config.backends) || config.backends.length === 0) {
    throw new ConfigValidationError('Config must have at least one backend', 'backends')
  }

  const backends: BackendConfig[] = config.backends.map((entry: unknown, i: number) =>
    validateBackendEntry(entry, i),
  )

  if (!isObject(config.keyRotation)) {
    throw new ConfigValidationError('Config keyRotation must be an object', 'keyRotation')
  }
  if (
    typeof config.keyRotation.gracePeriodDays !== 'number' ||
    config.keyRotation.gracePeriodDays <= 0
  ) {
    throw new ConfigValidationError(
      'Config keyRotation.gracePeriodDays must be a positive number',
      'keyRotation.gracePeriodDays',
    )
  }

  if (!isObject(config.defaults)) {
    throw new ConfigValidationError('Config defaults must be an object', 'defaults')
  }
  if (typeof config.defaults.ttlMinutes !== 'number' || config.defaults.ttlMinutes <= 0) {
    throw new ConfigValidationError(
      'Config defaults.ttlMinutes must be a positive number',
      'defaults.ttlMinutes',
    )
  }
  // Coerce string trust tier values from Rust CLI config (which serializes as "1"/"2"/"3")
  let tier: unknown = config.defaults.trustTier
  if (typeof tier === 'string') {
    const parsed = Number(tier)
    if (!Number.isNaN(parsed)) {
      tier = parsed
    }
  }
  if (tier !== 1 && tier !== 2 && tier !== 3) {
    throw new ConfigValidationError(
      'Config defaults.trustTier must be 1, 2, or 3',
      'defaults.trustTier',
    )
  }

  const result: VaultConfig = {
    version: 1,
    backends,
    keyRotation: {
      gracePeriodDays: config.keyRotation.gracePeriodDays,
    },
    defaults: {
      ttlMinutes: config.defaults.ttlMinutes,
      trustTier: tier satisfies TrustTier,
    },
  }

  if (config.developmentMode !== undefined) {
    if (!isObject(config.developmentMode)) {
      throw new ConfigValidationError('Config developmentMode must be an object', 'developmentMode')
    }
    if (!Array.isArray(config.developmentMode.executables)) {
      throw new ConfigValidationError(
        'Config developmentMode.executables must be an array',
        'developmentMode.executables',
      )
    }
    const executables: string[] = []
    for (const [i, exe] of Array.from(config.developmentMode.executables).entries()) {
      if (typeof exe !== 'string') {
        throw new ConfigValidationError(
          `Config developmentMode.executables[${String(i)}] must be a string`,
          `developmentMode.executables[${String(i)}]`,
        )
      }
      executables.push(exe)
    }
    result.developmentMode = { executables }
  }

  return result
}

/**
 * Load the vaultkeeper config from disk, falling back to defaults if the file
 * does not exist.
 *
 * @param configDir - Directory containing config.json. Defaults to platform-appropriate path.
 * @public
 */
export async function loadConfig(configDir?: string): Promise<VaultConfig> {
  const dir = configDir ?? getDefaultConfigDir()
  const configPath = path.join(dir, 'config.json')

  let raw: string
  try {
    raw = await fs.readFile(configPath, 'utf-8')
  } catch {
    return defaultConfig()
  }

  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch {
    throw new Error(`Failed to parse config file at ${configPath}`)
  }

  return validateConfig(parsed)
}
