/**
 * Configuration loading, validation, and defaults for vaultkeeper.
 */

import * as fs from 'node:fs/promises'
import * as path from 'node:path'
import * as os from 'node:os'
import type { VaultConfig, BackendConfig, TrustTier } from './types.js'
import { ConfigValidationError, ConfigParseError, FilesystemError } from './errors.js'

/**
 * Remediation hint appended to every config-loading error message so a user
 * always has a concrete next step, regardless of whether the failure was a
 * read error, a JSON syntax error, or a schema validation error (issue #68).
 *
 * This library has no CLI of its own (`vaultkeeper` ships no `bin`), so the
 * hint is qualified rather than naming a bare command: install the separate
 * `@vaultkeeper/cli` package to run `vaultkeeper config init --force`, or fix
 * the config through the JS API directly (issue #100).
 */
const CONFIG_REMEDIATION_HINT = `Fix the file — either install @vaultkeeper/cli and run 'vaultkeeper config init --force' to overwrite it with a valid config, or repair/replace it programmatically via this library (pass an explicit \`config\` or \`configDir\`, or write a valid config.json yourself).`

/** `true` if `err` is a Node.js filesystem error with the given `code`. */
function hasErrorCode(err: unknown, code: string): boolean {
  return err instanceof Error && 'code' in err && err.code === code
}

/** Extract a readable message from an unknown thrown value. */
function describeError(err: unknown): string {
  return err instanceof Error ? err.message : String(err)
}

/**
 * Best-effort human-readable location (`'line X, column Y'`) derived from a
 * JSON `SyntaxError`. Modern V8 (Node 20+) already includes `line N column N`
 * in the message; older engines only report a character offset (`position
 * N`), which this falls back to converting by counting newlines in `raw`.
 * Returns `undefined` when no location can be determined.
 */
function describeJsonSyntaxLocation(err: unknown, raw: string): string | undefined {
  const message = describeError(err)

  const lineColMatch = /line (\d+) column (\d+)/.exec(message)
  if (lineColMatch) {
    return `line ${lineColMatch[1] ?? ''}, column ${lineColMatch[2] ?? ''}`
  }

  const positionMatch = /position (\d+)/.exec(message)
  if (positionMatch) {
    const posStr = positionMatch[1]
    const pos = posStr !== undefined ? Number(posStr) : NaN
    if (!Number.isNaN(pos) && pos >= 0 && pos <= raw.length) {
      const upToPos = raw.slice(0, pos)
      const line = upToPos.split('\n').length
      const column = pos - upToPos.lastIndexOf('\n')
      return `line ${String(line)}, column ${String(column)}`
    }
  }

  return undefined
}

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
 * The backend type vaultkeeper uses by default when no backend is explicitly
 * configured — the **`file`** backend, on every platform.
 *
 * @remarks
 * The zero-config default is deliberately the portable, self-contained
 * AES-256-GCM encrypted file backend rather than the platform-native OS
 * credential store. This guarantees that a bare {@link VaultKeeper.init} — or a
 * `vaultkeeper config init` (run via the separate `@vaultkeeper/cli` package)
 * with no `--backend` flag — can never silently write a secret into the
 * user's real login keychain (or Windows DPAPI store) before they have
 * chosen to. It also matches the WASM SDK, which always uses the file
 * backend.
 *
 * The OS-native store is still available as an explicit opt-in: pass
 * `--backend keychain` (macOS) / `--backend dpapi` (Windows) to
 * `vaultkeeper config init` (via `@vaultkeeper/cli`), or set
 * `{ type: 'keychain' | 'dpapi' }` directly in a config object/file. Use
 * {@link platformNativeBackendType} to discover which native store the current
 * platform offers.
 *
 * @returns The zero-config default backend type identifier (`'file'`).
 * @public
 */
export function defaultBackendType(): string {
  return 'file'
}

/**
 * Resolve the OS-native credential store type for the current platform.
 *
 * @remarks
 * This is **not** the zero-config default — {@link defaultBackendType} (always
 * `'file'`) is. This function reports which platform-native store a user can
 * explicitly opt into (e.g. via `vaultkeeper config init --backend keychain`
 * from the separate `@vaultkeeper/cli` package, or `{ type: 'keychain' }` in
 * a config object/file passed directly to this library):
 *
 * - **macOS** → `keychain` (macOS Keychain)
 * - **Windows** → `dpapi` (Windows DPAPI)
 * - **Linux** → `secret-tool` (Secret Service via `libsecret`; opting in
 *   requires the `libsecret-tools` package)
 * - **any other platform** → `file` (no built-in native store integration, so
 *   the portable AES-256-GCM encrypted file backend is the only option)
 *
 * Use it to tell the user which native store is available on their platform, or
 * to label the opt-in. It never affects what an unconfigured vault resolves to
 * — that is always {@link defaultBackendType} (`file`).
 *
 * @returns The OS-native backend type identifier for the current platform.
 * @public
 */
export function platformNativeBackendType(): string {
  if (process.platform === 'darwin') {
    return 'keychain'
  }
  if (process.platform === 'win32') {
    return 'dpapi'
  }
  if (process.platform === 'linux') {
    // The `secret-tool` backend is a real shipped built-in (Secret Service via
    // libsecret) — the Linux OS-native store a user can opt into. It is not the
    // zero-config default (that is `file`), so naming it here never risks a
    // silent write: the caller must explicitly choose `--backend secret-tool`.
    return 'secret-tool'
  }
  // Other platforms (e.g. the BSDs) have no built-in native-store integration.
  return 'file'
}

/**
 * Default configuration when no config file exists.
 *
 * The active backend is the safe zero-config default resolved by
 * {@link defaultBackendType} (the `file` backend on every platform), never the
 * OS-native credential store — a missing config must never silently target the
 * real keychain (issue #98).
 */
function defaultConfig(): VaultConfig {
  return {
    version: 1,
    backends: [{ type: defaultBackendType(), enabled: true }],
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
 * Load the vaultkeeper config from disk, falling back to platform defaults
 * only when the config file is missing (`ENOENT`).
 *
 * Any other read failure (e.g. `EACCES`, `EISDIR`) is a genuinely broken or
 * unreadable config and is rethrown as a {@link FilesystemError} rather than
 * silently defaulted — silently defaulting on a permissions error would hide
 * the problem from `doctor` and `config show` (issue #68). A present file
 * that fails to parse as JSON throws {@link ConfigParseError}; a present file
 * that parses but fails schema validation throws {@link ConfigValidationError}.
 * All three error messages include the config file path and a remediation
 * hint naming `vaultkeeper config init --force` (via the separate
 * `@vaultkeeper/cli` package) as well as the JS-API alternative of repairing
 * or replacing the config directly — the supported recovery paths for an
 * existing-but-broken config (issues #97, #100).
 *
 * @param configDir - Directory containing config.json. Defaults to
 * `getDefaultConfigDir()`, which itself honors `VAULTKEEPER_CONFIG_DIR`
 * before falling back to the platform-appropriate path.
 * @public
 */
export async function loadConfig(configDir?: string): Promise<VaultConfig> {
  const dir = configDir ?? getDefaultConfigDir()
  const configPath = path.join(dir, 'config.json')

  let raw: string
  try {
    raw = await fs.readFile(configPath, 'utf-8')
  } catch (err) {
    if (hasErrorCode(err, 'ENOENT')) {
      return defaultConfig()
    }
    throw new FilesystemError(
      `Cannot read config file at ${configPath}: ${describeError(err)}. ${CONFIG_REMEDIATION_HINT}`,
      configPath,
      'read',
      err,
    )
  }

  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch (err) {
    const location = describeJsonSyntaxLocation(err, raw)
    const locationSuffix = location !== undefined ? ` at ${location}` : ''
    throw new ConfigParseError(
      `Failed to parse config file at ${configPath}${locationSuffix}: ${describeError(err)}. ` +
        CONFIG_REMEDIATION_HINT,
      configPath,
      location,
    )
  }

  try {
    return validateConfig(parsed)
  } catch (err) {
    if (err instanceof ConfigValidationError) {
      throw new ConfigValidationError(
        `Invalid config at ${configPath}: ${err.message} ${CONFIG_REMEDIATION_HINT}`,
        err.field,
        configPath,
      )
    }
    throw err
  }
}
