import { parseArgs } from 'node:util'
import * as fs from 'node:fs/promises'
import * as path from 'node:path'
import * as os from 'node:os'
import { formatError } from '../output.js'

function getDefaultConfigDir(): string {
  if (process.platform === 'win32') {
    const appData = process.env.APPDATA
    if (appData !== undefined) {
      return path.join(appData, 'vaultkeeper')
    }
    return path.join(os.homedir(), 'AppData', 'Roaming', 'vaultkeeper')
  }
  return path.join(os.homedir(), '.config', 'vaultkeeper')
}

const DEFAULT_CONFIG = JSON.stringify(
  {
    version: 1,
    backends: [{ type: 'keychain', enabled: true }],
    keyRotation: { gracePeriodDays: 7 },
    defaults: { ttlMinutes: 60, trustTier: 3 },
  },
  null,
  2,
)

export async function configCommand(args: string[]): Promise<number> {
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

        await fs.writeFile(configPath, DEFAULT_CONFIG + '\n', { encoding: 'utf8', mode: 0o600 })
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
        process.stderr.write(`${formatError(err)}\n`)
        return 1
      }
    }

    default:
      process.stderr.write('Usage: vaultkeeper config <init|show>\n')
      return 1
  }
}
