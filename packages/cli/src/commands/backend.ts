/**
 * The `vaultkeeper backend` command group — introspection over the registered
 * secret backends.
 *
 * Currently exposes a single subcommand, `capabilities`, which reports each
 * registered backend's security capabilities (notably `presencePerUse`) so a
 * consumer can discover — without touching any credential — which backend can
 * satisfy a `--require-presence-per-use` requirement.
 *
 * @internal
 */

import { parseArgs } from 'node:util'
import {
  BackendRegistry,
  getBackendCapabilities,
  loadConfig,
  type BackendConfig,
  type SecretBackend,
} from 'vaultkeeper'
import { formatError } from '../output.js'
import { CONFIG_DIR_HELP_OPTION, CONFIG_DIR_HELP_ENV } from '../config-dir.js'

/**
 * One row of `backend capabilities` output: a registered backend and the
 * capabilities its **configured instance** advertises.
 *
 * This is the documented JSON shape emitted by `--json` (a flat array of these).
 */
interface BackendCapabilityRow {
  /** Backend type identifier (e.g. `'file'`, `'yubikey'`, `'1password'`). */
  type: string
  /** Human-readable backend name (e.g. `'YubiKey'`). */
  displayName: string
  /**
   * Whether the configured instance forces a distinct, fresh per-use human
   * action for every keyed operation (never satisfiable from a cached/session
   * state). See `BackendCapabilities.presencePerUse`.
   */
  presencePerUse: boolean
}

function printBackendHelp(): void {
  process.stdout.write(
    'Usage: vaultkeeper backend <subcommand> [options]\n\n' +
      'Subcommands:\n' +
      '  capabilities   List each registered backend and its security capabilities\n\n' +
      'Options:\n' +
      '  --json         Emit machine-readable JSON instead of human-readable text\n' +
      CONFIG_DIR_HELP_OPTION +
      '  -h, --help     Show this help message\n\n' +
      'Environment variables:\n' +
      CONFIG_DIR_HELP_ENV,
  )
}

/**
 * Build one capability row per registered backend, reflecting each backend's
 * **configured instance** (so a YubiKey slot's touch policy or 1Password's
 * access mode is honored). Instantiation and capability probing are read-only
 * and never trigger a human-presence prompt; a backend whose factory or probe
 * throws is reported with the safe default (`presencePerUse: false`) rather than
 * omitted, so the enumeration stays complete.
 */
async function collectCapabilities(configDir: string): Promise<BackendCapabilityRow[]> {
  // Load config (falls back to defaults when no file exists) so each backend is
  // probed as its configured instance where one is present.
  const config = await loadConfig(configDir)
  const configByType = new Map<string, BackendConfig>()
  for (const backendConfig of config.backends) {
    if (!configByType.has(backendConfig.type)) {
      configByType.set(backendConfig.type, backendConfig)
    }
  }

  const types = BackendRegistry.getTypes().sort((a, b) => a.localeCompare(b))
  const rows = await Promise.all(
    types.map(async (type): Promise<BackendCapabilityRow> => {
      let backend: SecretBackend
      try {
        backend = BackendRegistry.create(type, configByType.get(type), configDir)
      } catch {
        // A factory that cannot build a default instance still gets a row, so
        // the enumeration is exhaustive. It cannot claim a capability it could
        // not be probed for.
        return { type, displayName: type, presencePerUse: false }
      }
      try {
        const capabilities = await getBackendCapabilities(backend)
        return {
          type,
          displayName: backend.displayName,
          presencePerUse: capabilities.presencePerUse,
        }
      } catch {
        return { type, displayName: backend.displayName, presencePerUse: false }
      }
    }),
  )
  return rows
}

/** Render the capability rows as aligned, human-readable text. */
function renderHumanReadable(rows: BackendCapabilityRow[]): string {
  const header = 'Backend capabilities (per configured instance):\n\n'
  const typeWidth = Math.max(0, ...rows.map((r) => r.type.length))
  const nameWidth = Math.max(0, ...rows.map((r) => r.displayName.length))
  const lines = rows.map((row) => {
    const presence = row.presencePerUse ? 'yes' : 'no'
    return `  ${row.type.padEnd(typeWidth)}  ${row.displayName.padEnd(nameWidth)}  presence-per-use: ${presence}`
  })
  const footer =
    '\n\nA backend with presence-per-use: yes forces a distinct, fresh human action\n' +
    'per operation and can satisfy `--require-presence-per-use`.\n'
  return `${header}${lines.join('\n')}${footer}`
}

async function capabilitiesSubcommand(args: string[], configDir: string): Promise<number> {
  let values: { json: boolean }
  try {
    ;({ values } = parseArgs({
      args,
      options: {
        json: { type: 'boolean', default: false },
      },
      strict: true,
    }))
  } catch (err) {
    if (err instanceof Error) {
      process.stderr.write(`Error: ${err.message}\n`)
    }
    process.stderr.write('Usage: vaultkeeper backend capabilities [--json]\n')
    return 2
  }

  try {
    const rows = await collectCapabilities(configDir)
    if (values.json) {
      process.stdout.write(`${JSON.stringify(rows, null, 2)}\n`)
    } else {
      process.stdout.write(renderHumanReadable(rows))
    }
    return 0
  } catch (err) {
    process.stderr.write(`${formatError(err, configDir)}\n`)
    return 1
  }
}

export async function backendCommand(args: string[], configDir: string): Promise<number> {
  if (args.includes('--help') || args.includes('-h')) {
    printBackendHelp()
    return 0
  }

  const subcommand = args[0]
  if (subcommand === undefined) {
    process.stderr.write('Error: a subcommand is required\n')
    printBackendHelp()
    return 2
  }

  switch (subcommand) {
    case 'capabilities':
      return capabilitiesSubcommand(args.slice(1), configDir)
    default:
      process.stderr.write(`Error: unknown backend subcommand '${subcommand}'\n`)
      printBackendHelp()
      return 2
  }
}
