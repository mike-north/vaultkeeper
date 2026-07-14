import { parseArgs } from 'node:util'
import * as fs from 'node:fs/promises'
import * as path from 'node:path'
import { BackendRegistry, platformDefaultBackendType } from 'vaultkeeper'
import { formatError } from '../output.js'
import { CONFIG_DIR_HELP_OPTION, CONFIG_DIR_HELP_ENV } from '../config-dir.js'

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
      `                     (valid: ${BackendRegistry.getTypes().join(', ')})\n\n` +
      'Options:\n' +
      CONFIG_DIR_HELP_OPTION +
      '  -h, --help   Show this help message\n\n' +
      'Environment variables:\n' +
      CONFIG_DIR_HELP_ENV,
  )
}

/** Return true if err is a Node.js ENOENT error (file not found). */
function isEnoent(err: unknown): boolean {
  return err instanceof Error && 'code' in err && err.code === 'ENOENT'
}

async function configInit(rest: string[], configDir: string): Promise<number> {
  const unknownFlag = findUnknownFlag(rest, new Set(['backend']))
  if (unknownFlag !== undefined) {
    process.stderr.write(`Error: unknown option '${unknownFlag}' for 'config init'\n`)
    return 2
  }

  const { values } = parseArgs({
    args: rest,
    options: { backend: { type: 'string' } },
    allowPositionals: true,
    strict: false,
  })

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

    try {
      await fs.access(configPath)
      process.stderr.write(`Config already exists at ${configPath}\n`)
      return 1
    } catch {
      // File doesn't exist — create it.
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
  const unknownFlag = findUnknownFlag(rest, new Set())
  if (unknownFlag !== undefined) {
    process.stderr.write(`Error: unknown option '${unknownFlag}' for 'config show'\n`)
    return 2
  }

  try {
    const configPath = path.join(configDir, 'config.json')
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
    // Show a user-friendly message when the config file is missing.
    if (isEnoent(err)) {
      process.stderr.write(
        "Error: No config file found. Run 'vaultkeeper config init' to create one.\n",
      )
      return 1
    }
    process.stderr.write(`${formatError(err)}\n`)
    return 1
  }
}

export async function configCommand(args: string[], configDir: string): Promise<number> {
  // Handle --help / -h before subcommand dispatch.
  if (args.includes('--help') || args.includes('-h')) {
    printConfigHelp()
    return 0
  }

  const subcommand = args[0]
  const rest = args.slice(1)

  switch (subcommand) {
    case 'init':
      return configInit(rest, configDir)

    case 'show':
      return configShow(rest, configDir)

    default:
      process.stderr.write('Error: missing or unknown config subcommand\n')
      process.stderr.write('Usage: vaultkeeper config <init|show>\n')
      // Exit code 2: usage error (missing or unknown subcommand)
      return 2
  }
}
