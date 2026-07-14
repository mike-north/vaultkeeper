import { parseArgs } from 'node:util'
import * as path from 'node:path'
import { VaultKeeper } from 'vaultkeeper'
import { formatError } from '../output.js'
import { CONFIG_DIR_HELP_OPTION, CONFIG_DIR_HELP_ENV } from '../config-dir.js'

function printApproveHelp(): void {
  process.stdout.write(
    'Usage: vaultkeeper approve --script <path>\n\n' +
      'Record a script hash in the TOFU trust manifest so that invoking it via\n' +
      'vaultkeeper exec does not prompt for trust. Running this on an already\n' +
      'approved, unchanged script is idempotent.\n\n' +
      'Options:\n' +
      '  --script <path>   Path to the script to approve\n' +
      CONFIG_DIR_HELP_OPTION +
      '  -h, --help        Show this help message\n\n' +
      'Environment variables:\n' +
      CONFIG_DIR_HELP_ENV,
  )
}

export async function approveCommand(args: string[], configDir: string): Promise<number> {
  // Handle --help / -h before strict parseArgs.
  if (args.includes('--help') || args.includes('-h')) {
    printApproveHelp()
    return 0
  }

  const { values } = parseArgs({
    args,
    options: {
      script: { type: 'string' },
    },
    strict: true,
  })

  if (values.script === undefined) {
    process.stderr.write('Error: --script is required\n')
    process.stderr.write('Usage: vaultkeeper approve --script <path>\n')
    // Exit code 2: usage error (missing required flag)
    return 2
  }

  const scriptPath = path.resolve(values.script)

  try {
    // Approving a hash is a trust-only operation: it touches the config dir and
    // trust manifest, never the secret backend. Skip the doctor preflight, and
    // VaultKeeper.init() itself resolves the backend lazily, so approve works
    // even when the configured backend or plugin is unavailable.
    const vault = await VaultKeeper.init({ configDir, skipDoctor: true })
    const status = await vault.approveExecutable(scriptPath)
    process.stdout.write(`Approved ${scriptPath} (hash: ${status.hash})\n`)
    return 0
  } catch (err) {
    process.stderr.write(`${formatError(err)}\n`)
    // Exit code 1: runtime error (e.g. missing script, unwritable manifest)
    return 1
  }
}
