import { parseArgs } from 'node:util'
import * as path from 'node:path'
import { VaultKeeper } from 'vaultkeeper'
import { formatError } from '../output.js'

function printApproveHelp(): void {
  process.stdout.write(
    'Usage: vaultkeeper approve --script <path>\n\n' +
      'Record a script hash in the TOFU trust manifest so that invoking it via\n' +
      'vaultkeeper exec does not prompt for trust. Running this on an already\n' +
      'approved, unchanged script is idempotent.\n\n' +
      'Options:\n' +
      '  --script <path>   Path to the script to approve\n' +
      '  -h, --help        Show this help message\n',
  )
}

export async function approveCommand(args: string[]): Promise<number> {
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
    // Approving a hash does not need backend health, so skip doctor preflight.
    const vault = await VaultKeeper.init({ skipDoctor: true })
    const status = await vault.approveExecutable(scriptPath)
    process.stdout.write(`Approved ${scriptPath} (hash: ${status.hash})\n`)
    return 0
  } catch (err) {
    process.stderr.write(`${formatError(err)}\n`)
    // Exit code 1: runtime error (e.g. missing script, unwritable manifest)
    return 1
  }
}
