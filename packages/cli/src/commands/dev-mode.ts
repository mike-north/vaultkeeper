import { parseArgs } from 'node:util'
import * as path from 'node:path'
import { VaultKeeper } from 'vaultkeeper'
import { formatError } from '../output.js'

function printDevModeHelp(): void {
  process.stdout.write(
    'Usage: vaultkeeper dev-mode <enable|disable> --script <path>\n\n' +
      'Toggle development mode for a script. In development mode the executable\n' +
      'hash check is relaxed so the script can be modified without re-approval.\n\n' +
      'Arguments:\n' +
      '  enable | disable   Action to perform\n\n' +
      'Options:\n' +
      '  --script <path>   Path to the script\n' +
      '  -h, --help        Show this help message\n',
  )
}

export async function devModeCommand(args: string[]): Promise<number> {
  // Handle --help / -h before parseArgs.
  if (args.includes('--help') || args.includes('-h')) {
    printDevModeHelp()
    return 0
  }

  const { positionals, values } = parseArgs({
    args,
    allowPositionals: true,
    options: {
      script: { type: 'string' },
    },
    strict: true,
  })

  const action = positionals[0]

  if ((action !== 'enable' && action !== 'disable') || values.script === undefined) {
    process.stderr.write('Usage: vaultkeeper dev-mode <enable|disable> --script <path>\n')
    // Exit code 2: usage error (missing action or --script)
    return 2
  }

  const scriptPath = path.resolve(values.script)
  const enabled = action === 'enable'

  try {
    const vault = await VaultKeeper.init()
    await vault.setDevelopmentMode(scriptPath, enabled)
    process.stdout.write(
      `Development mode ${enabled ? 'enabled' : 'disabled'} for ${scriptPath}\n`,
    )
    return 0
  } catch (err) {
    process.stderr.write(`${formatError(err)}\n`)
    return 1
  }
}
