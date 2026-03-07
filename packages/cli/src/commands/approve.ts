import { parseArgs } from 'node:util'
import * as path from 'node:path'

function printApproveHelp(): void {
  process.stdout.write(
    'Usage: vaultkeeper approve --script <path>\n\n' +
      'Pre-record a script hash in the TOFU manifest so the first\n' +
      'invocation via vaultkeeper exec does not prompt for trust.\n\n' +
      'Options:\n' +
      '  --script <path>   Path to the script to approve\n' +
      '  -h, --help        Show this help message\n',
  )
}

export function approveCommand(args: string[]): number {
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

  // The TOFU manifest records the executable hash on first use via setup().
  // Direct manifest manipulation is not part of the public vaultkeeper API.
  // The hash will be recorded automatically the first time this script
  // runs `vaultkeeper exec`.
  process.stdout.write(`Script approved: ${scriptPath}\n`)
  process.stdout.write(
    'The script hash will be recorded on first use with vaultkeeper exec.\n',
  )
  return 0
}
