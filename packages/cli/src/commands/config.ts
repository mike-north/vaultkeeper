import { parseArgs } from 'node:util'
import * as fs from 'node:fs/promises'
import * as path from 'node:path'
import { BackendRegistry, platformDefaultBackendType, loadConfig } from 'vaultkeeper'
import { formatError } from '../output.js'
import { CONFIG_DIR_HELP_OPTION, CONFIG_DIR_HELP_ENV } from '../config-dir.js'
import { configFileExists, noConfigMessage } from '../config-status.js'

/** Human-readable name for the current platform, for user-facing messages. */
function platformLabel(): string {
  if (process.platform === 'darwin') {
    return 'macOS'
  }
  if (process.platform === 'win32') {
    return 'Windows'
  }
  return 'Linux'
}

/** Serialize a default config whose first enabled backend is `backendType`. */
function buildConfig(backendType: string): string {
  const config: Record<string, unknown> = {
    version: 1,
    backends: [{ type: backendType, enabled: true }],
    keyRotation: { gracePeriodDays: 7 },
    defaults: { ttlMinutes: 60, trustTier: 3 },
  }
  return JSON.stringify(config, null, 2)
}

/** Narrow an unknown value to an enabled backend entry with a string type. */
function isEnabledBackendEntry(entry: unknown): entry is { type: string; enabled: true } {
  return (
    typeof entry === 'object' &&
    entry !== null &&
    'enabled' in entry &&
    entry.enabled === true &&
    'type' in entry &&
    typeof entry.type === 'string'
  )
}

/**
 * Return the type of the first enabled backend described by a config file's
 * JSON contents, or `undefined` if none can be resolved.
 */
function firstEnabledBackendType(content: string): string | undefined {
  let parsed: unknown
  try {
    parsed = JSON.parse(content)
  } catch {
    return undefined
  }
  if (typeof parsed !== 'object' || parsed === null || !('backends' in parsed)) {
    return undefined
  }
  const backends: unknown = parsed.backends
  if (!Array.isArray(backends)) {
    return undefined
  }
  const entries: readonly unknown[] = backends
  for (const entry of entries) {
    if (isEnabledBackendEntry(entry)) {
      return entry.type
    }
  }
  return undefined
}

/**
 * Reject any flag in `rest` that is not in `allowed`. Returns the raw form of
 * the first unknown flag encountered, or `undefined` if all flags are allowed.
 * A typo in a flag name must never be silently ignored — it could route
 * secrets to an unintended credential store.
 */
function findUnknownFlag(rest: string[], allowed: ReadonlySet<string>): string | undefined {
  const { tokens } = parseArgs({ args: rest, strict: false, allowPositionals: true, tokens: true })
  for (const token of tokens) {
    if (token.kind === 'option' && !allowed.has(token.name)) {
      return token.rawName
    }
  }
  return undefined
}

function printConfigHelp(): void {
  process.stdout.write(
    'Usage: vaultkeeper config <subcommand>\n\n' +
      'Subcommands:\n' +
      '  init   Create a default config file\n' +
      '  show   Print the current config file\n\n' +
      'Options for init:\n' +
      '  --backend <type>   Backend to configure as the active store\n' +
      `                     (valid: ${BackendRegistry.getTypes().join(', ')})\n` +
      '  --force            Overwrite an existing (or corrupt) config file\n\n' +
      'Options:\n' +
      CONFIG_DIR_HELP_OPTION +
      '  -h, --help   Show this help message\n\n' +
      'Run "vaultkeeper config <subcommand> --help" for subcommand-specific help.\n\n' +
      'Environment variables:\n' +
      CONFIG_DIR_HELP_ENV,
  )
}

function printConfigInitHelp(): void {
  process.stdout.write(
    'Usage: vaultkeeper config init [--backend <type>] [--force]\n\n' +
      'Create a default config file.\n\n' +
      'Options:\n' +
      '  --backend <type>   Backend to configure as the active store\n' +
      `                     (valid: ${BackendRegistry.getTypes().join(', ')})\n` +
      '  --force            Overwrite an existing (or corrupt/unparseable)\n' +
      '                     config file instead of refusing\n' +
      CONFIG_DIR_HELP_OPTION +
      '  -h, --help         Show this help message\n\n' +
      'Environment variables:\n' +
      CONFIG_DIR_HELP_ENV,
  )
}

function printConfigShowHelp(): void {
  process.stdout.write(
    'Usage: vaultkeeper config show\n\n' +
      'Print the current config file (or platform defaults, with a notice on\n' +
      'stderr, when no config file exists).\n\n' +
      'Options:\n' +
      CONFIG_DIR_HELP_OPTION +
      '  -h, --help   Show this help message\n\n' +
      'Environment variables:\n' +
      CONFIG_DIR_HELP_ENV,
  )
}

async function configInit(rest: string[], configDir: string): Promise<number> {
  // Handle --help / -h before findUnknownFlag so it isn't rejected as an
  // unrecognized flag for 'config init'.
  if (rest.includes('--help') || rest.includes('-h')) {
    printConfigInitHelp()
    return 0
  }

  const unknownFlag = findUnknownFlag(rest, new Set(['backend', 'force']))
  if (unknownFlag !== undefined) {
    process.stderr.write(`Error: unknown option '${unknownFlag}' for 'config init'\n`)
    return 2
  }

  const { values } = parseArgs({
    args: rest,
    options: { backend: { type: 'string' }, force: { type: 'boolean' } },
    allowPositionals: true,
    strict: false,
  })
  const force = values.force === true

  let requestedBackend: string | undefined
  if (values.backend !== undefined) {
    if (typeof values.backend !== 'string' || values.backend.trim() === '') {
      process.stderr.write('Error: --backend requires a backend type value\n')
      return 2
    }
    const validTypes = BackendRegistry.getTypes()
    if (!validTypes.includes(values.backend)) {
      process.stderr.write(
        `Error: unknown backend type '${values.backend}'. Valid types: ${validTypes.join(', ')}\n`,
      )
      return 2
    }
    requestedBackend = values.backend
  }

  const backendType = requestedBackend ?? platformDefaultBackendType()

  try {
    const configPath = path.join(configDir, 'config.json')
    // Create config directory with restrictive permissions.
    await fs.mkdir(configDir, { recursive: true, mode: 0o700 })

    if (!force) {
      try {
        await fs.access(configPath)
        process.stderr.write(
          `Config already exists at ${configPath}\n` +
            "Run 'vaultkeeper config init --force' to overwrite it.\n",
        )
        return 1
      } catch {
        // File doesn't exist — create it.
      }
    }

    await fs.writeFile(configPath, buildConfig(backendType) + '\n', {
      encoding: 'utf8',
      mode: 0o600,
    })
    process.stdout.write(`Config created at ${configPath}\n`)

    if (requestedBackend === undefined) {
      if (backendType === 'file') {
        process.stdout.write(
          `Backend: file (${platformLabel()} default). ` +
            'Use --backend <type> to target an OS credential store.\n',
        )
      } else {
        process.stdout.write(
          `Backend: ${backendType} (${platformLabel()} default). ` +
            'Use --backend file for a portable, CI-friendly store.\n',
        )
      }
    } else {
      process.stdout.write(
        `Backend: ${backendType} (from --backend). ` +
          "Re-run 'vaultkeeper config init --backend <type>' to change.\n",
      )
    }
    return 0
  } catch (err) {
    process.stderr.write(`${formatError(err)}\n`)
    return 1
  }
}

async function configShow(rest: string[], configDir: string): Promise<number> {
  // Handle --help / -h before findUnknownFlag so it isn't rejected as an
  // unrecognized flag for 'config show'.
  if (rest.includes('--help') || rest.includes('-h')) {
    printConfigShowHelp()
    return 0
  }

  const unknownFlag = findUnknownFlag(rest, new Set())
  if (unknownFlag !== undefined) {
    process.stderr.write(`Error: unknown option '${unknownFlag}' for 'config show'\n`)
    return 2
  }

  const configPath = path.join(configDir, 'config.json')
  try {
    const exists = await configFileExists(configDir)

    // loadConfig is the single source of truth for "is this config valid":
    // it throws a typed, path-and-remediation-bearing error (ConfigParseError
    // / ConfigValidationError / FilesystemError) on anything but a missing
    // file, and never returns from a present-but-broken config. This makes
    // an invalid config a hard failure (never a raw dump with exit 0), per
    // issue #68.
    const config = await loadConfig(configDir)

    if (!exists) {
      // No config file: fall back to platform defaults and say so, the same
      // story store/delete/exec/doctor use (issue #68) — never error here.
      const activeType =
        config.backends.find((b) => b.enabled)?.type ?? platformDefaultBackendType()
      process.stderr.write(noConfigMessage(activeType))
      process.stdout.write(`${JSON.stringify(config, null, 2)}\n`)
      process.stderr.write(`Active backend: ${activeType} (platform default)\n`)
      return 0
    }

    // File exists and is valid — dump the raw file content (preserving its
    // exact formatting) rather than the re-serialized, normalized config.
    const content = await fs.readFile(configPath, 'utf8')
    // The loaded path is a diagnostic, so it goes to stderr — stdout
    // stays pure JSON for consumers that pipe/parse `config show`.
    process.stderr.write(`Loaded from: ${configPath}\n`)
    process.stdout.write(content)
    if (!content.endsWith('\n')) {
      process.stdout.write('\n')
    }
    // Report the resolved active backend on stderr so stdout stays valid JSON.
    const active = firstEnabledBackendType(content)
    if (active !== undefined) {
      process.stderr.write(`Active backend: ${active} (first enabled)\n`)
    } else {
      process.stderr.write('Active backend: none (no enabled backend found)\n')
    }
    return 0
  } catch (err) {
    process.stderr.write(`${formatError(err)}\n`)
    return 1
  }
}

export async function configCommand(args: string[], configDir: string): Promise<number> {
  const subcommand = args[0]
  const rest = args.slice(1)

  switch (subcommand) {
    case 'init':
      // --help / -h is handled inside configInit so it prints init-specific
      // help, not the parent 'config' help (regression: issue #69).
      return configInit(rest, configDir)

    case 'show':
      // --help / -h is handled inside configShow so it prints show-specific
      // help, not the parent 'config' help (regression: issue #69).
      return configShow(rest, configDir)

    // Only a bare 'config --help'/'config -h' (no subcommand) shows the
    // parent help — a subcommand's own --help is handled above instead.
    case '--help':
    case '-h':
      printConfigHelp()
      return 0

    default:
      process.stderr.write('Error: missing or unknown config subcommand\n')
      process.stderr.write('Usage: vaultkeeper config <init|show>\n')
      // Exit code 2: usage error (missing or unknown subcommand)
      return 2
  }
}
