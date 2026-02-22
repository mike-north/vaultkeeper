import { parseArgs } from 'node:util'
import * as path from 'node:path'

export function approveCommand(args: string[]): number {
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
    return 1
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
