import { parseArgs } from 'node:util'
import * as path from 'node:path'
import { VaultKeeper } from 'vaultkeeper'
import { shouldSkipDoctor } from '../skip-doctor.js'
import { formatError } from '../output.js'
import { CONFIG_DIR_HELP_OPTION, CONFIG_DIR_HELP_ENV } from '../config-dir.js'

function printDevModeHelp(): void {
  process.stdout.write(
    'Usage: vaultkeeper dev-mode <enable|disable> --script <path>\n\n' +
      'Toggle development mode for a script. In development mode the executable\n' +
      'hash check is relaxed so the script can be modified without re-approval.\n\n' +
      'Arguments:\n' +
      '  enable | disable   Action to perform\n\n' +
      'Options:\n' +
      '  --script <path>    Path to the script\n' +
      '  --skip-doctor      Skip doctor preflight checks\n' +
      CONFIG_DIR_HELP_OPTION +
      '  -h, --help         Show this help message\n\n' +
      'Environment variables:\n' +
      '  VAULTKEEPER_SKIP_DOCTOR=1   Skip doctor preflight checks\n' +
      CONFIG_DIR_HELP_ENV,
  )
}

export async function devModeCommand(args: string[], configDir: string): Promise<number> {
  // Handle --help / -h before parseArgs.
  if (args.includes('--help') || args.includes('-h')) {
    printDevModeHelp()
    return 0
  }

  let positionals: string[]
  let values: { script?: string; 'skip-doctor': boolean }
  try {
    ;({ positionals, values } = parseArgs({
      args,
      allowPositionals: true,
      options: {
        script: { type: 'string' },
        'skip-doctor': { type: 'boolean', default: false },
      },
      strict: true,
    }))
  } catch (err) {
    // Regression: issue #69 — an unrecognized flag previously propagated
    // uncaught and exited 1 via bin.ts's fatal-error handler instead of the
    // usage-error exit code 2.
    if (err instanceof Error) {
      process.stderr.write(`Error: ${err.message}\n`)
    }
    process.stderr.write('Usage: vaultkeeper dev-mode <enable|disable> --script <path>\n')
    return 2
  }

  const action = positionals[0]

  if (action !== undefined && action !== 'enable' && action !== 'disable') {
    process.stderr.write(`Error: unknown action "${action}" (expected "enable" or "disable")\n`)
    process.stderr.write('Usage: vaultkeeper dev-mode <enable|disable> --script <path>\n')
    // Exit code 2: usage error (invalid action)
    return 2
  }

  if (action === undefined || values.script === undefined) {
    process.stderr.write('Error: missing action or --script flag\n')
    process.stderr.write('Usage: vaultkeeper dev-mode <enable|disable> --script <path>\n')
    // Exit code 2: usage error (missing action or --script)
    return 2
  }

  const scriptPath = path.resolve(values.script)
  const enabled = action === 'enable'
  const skipDoctor = shouldSkipDoctor(values['skip-doctor'])

  try {
    const vault = await VaultKeeper.init({ configDir, skipDoctor })
    await vault.setDevelopmentMode(scriptPath, enabled)
    process.stdout.write(`Development mode ${enabled ? 'enabled' : 'disabled'} for ${scriptPath}\n`)
    return 0
  } catch (err) {
    process.stderr.write(`${formatError(err, configDir)}\n`)
    return 1
  }
}
