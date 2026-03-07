import { parseArgs } from 'node:util'
import * as fs from 'node:fs/promises'
import * as path from 'node:path'
import * as os from 'node:os'
import { formatError } from '../output.js'

function getDefaultConfigDir(): string {
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

function getDefaultConfig(): string {
  let backendType: string
  if (process.platform === 'darwin') {
    backendType = 'keychain'
  } else if (process.platform === 'win32') {
    backendType = 'dpapi'
  } else {
    // Linux and other Unix-like systems.
    // Use 'file' rather than 'secret-tool' because secret-tool requires
    // installing libsecret-tools which many Linux systems don't have.
    backendType = 'file'
  }

  const config: Record<string, unknown> = {
    version: 1,
    backends: [{ type: backendType, enabled: true }],
    keyRotation: { gracePeriodDays: 7 },
    defaults: { ttlMinutes: 60, trustTier: 3 },
  }

  return JSON.stringify(config, null, 2)
}

function printConfigHelp(): void {
  process.stdout.write(
    'Usage: vaultkeeper config <subcommand>\n\n' +
      'Subcommands:\n' +
      '  init   Create a default config file\n' +
      '  show   Print the current config file\n\n' +
      'Options:\n' +
      '  -h, --help   Show this help message\n',
  )
}

/** Return true if err is a Node.js ENOENT error (file not found). */
function isEnoent(err: unknown): boolean {
  return err instanceof Error && 'code' in err && err.code === 'ENOENT'
}

export async function configCommand(args: string[]): Promise<number> {
  // Handle --help / -h before subcommand dispatch.
  if (args.includes('--help') || args.includes('-h')) {
    printConfigHelp()
    return 0
  }

  const { positionals } = parseArgs({
    args,
    allowPositionals: true,
    strict: false,
  })

  const subcommand = positionals[0]

  switch (subcommand) {
    case 'init': {
      try {
        const configDir = getDefaultConfigDir()
        const configPath = path.join(configDir, 'config.json')
        // [W4 fix] Create config directory with restrictive permissions
        await fs.mkdir(configDir, { recursive: true, mode: 0o700 })

        try {
          await fs.access(configPath)
          process.stderr.write(`Config already exists at ${configPath}\n`)
          return 1
        } catch {
          // File doesn't exist — create it
        }

        await fs.writeFile(configPath, getDefaultConfig() + '\n', { encoding: 'utf8', mode: 0o600 })
        process.stdout.write(`Config created at ${configPath}\n`)
        return 0
      } catch (err) {
        process.stderr.write(`${formatError(err)}\n`)
        return 1
      }
    }

    case 'show': {
      try {
        const configDir = getDefaultConfigDir()
        const configPath = path.join(configDir, 'config.json')
        const content = await fs.readFile(configPath, 'utf8')
        process.stdout.write(content)
        if (!content.endsWith('\n')) {
          process.stdout.write('\n')
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

    default:
      process.stderr.write('Error: missing or unknown config subcommand\n')
      process.stderr.write('Usage: vaultkeeper config <init|show>\n')
      // Exit code 2: usage error (missing or unknown subcommand)
      return 2
  }
}
