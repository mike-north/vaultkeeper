/**
 * Configuration loading, validation, and defaults for vaultkeeper.
 *
 * @packageDocumentation
 */

import * as fs from 'node:fs/promises'
import * as path from 'node:path'
import * as os from 'node:os'
import type { VaultConfig, BackendConfig, TrustTier } from './types.js'

/** Return the platform-appropriate default config directory. */
export function getDefaultConfigDir(): string {
  if (process.platform === 'win32') {
    const appData = process.env.APPDATA
    if (appData !== undefined) {
      return path.join(appData, 'vaultkeeper')
    }
    return path.join(os.homedir(), 'AppData', 'Roaming', 'vaultkeeper')
  }
  return path.join(os.homedir(), '.config', 'vaultkeeper')
}

/** Default configuration when no config file exists. */
function defaultConfig(): VaultConfig {
  return {
    version: 1,
    backends: [{ type: 'file', enabled: true }],
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
  if (!isObject(entry)) {
    throw new Error(`backends[${String(index)}] must be an object`)
  }
  if (typeof entry.type !== 'string' || entry.type.trim() === '') {
    throw new Error(`backends[${String(index)}].type must be a non-empty string`)
  }
  if (typeof entry.enabled !== 'boolean') {
    throw new Error(`backends[${String(index)}].enabled must be a boolean`)
  }

  const result: BackendConfig = {
    type: entry.type,
    enabled: entry.enabled,
  }

  if (entry.plugin !== undefined) {
    if (typeof entry.plugin !== 'boolean') {
      throw new Error(`backends[${String(index)}].plugin must be a boolean`)
    }
    result.plugin = entry.plugin
  }

  if (entry.path !== undefined) {
    if (typeof entry.path !== 'string') {
      throw new Error(`backends[${String(index)}].path must be a string`)
    }
    result.path = entry.path
  }

  return result
}

/**
 * Validate an unknown value as a VaultConfig, throwing on invalid structure.
 */
export function validateConfig(config: unknown): VaultConfig {
  if (!isObject(config)) {
    throw new Error('Config must be an object')
  }

  if (typeof config.version !== 'number' || config.version !== 1) {
    throw new Error('Config version must be 1')
  }

  if (!Array.isArray(config.backends) || config.backends.length === 0) {
    throw new Error('Config must have at least one backend')
  }

  const backends: BackendConfig[] = config.backends.map((entry: unknown, i: number) =>
    validateBackendEntry(entry, i),
  )

  if (!isObject(config.keyRotation)) {
    throw new Error('Config keyRotation must be an object')
  }
  if (
    typeof config.keyRotation.gracePeriodDays !== 'number' ||
    config.keyRotation.gracePeriodDays <= 0
  ) {
    throw new Error('Config keyRotation.gracePeriodDays must be a positive number')
  }

  if (!isObject(config.defaults)) {
    throw new Error('Config defaults must be an object')
  }
  if (typeof config.defaults.ttlMinutes !== 'number' || config.defaults.ttlMinutes <= 0) {
    throw new Error('Config defaults.ttlMinutes must be a positive number')
  }
  const tier = config.defaults.trustTier
  if (tier !== 1 && tier !== 2 && tier !== 3) {
    throw new Error('Config defaults.trustTier must be 1, 2, or 3')
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
      throw new Error('Config developmentMode must be an object')
    }
    if (!Array.isArray(config.developmentMode.executables)) {
      throw new Error('Config developmentMode.executables must be an array')
    }
    const executables: string[] = []
    for (const [i, exe] of Array.from(config.developmentMode.executables).entries()) {
      if (typeof exe !== 'string') {
        throw new Error(`Config developmentMode.executables[${String(i)}] must be a string`)
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
