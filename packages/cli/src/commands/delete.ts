import { parseArgs } from 'node:util'
import { VaultKeeper } from 'vaultkeeper'
import { shouldSkipDoctor } from '../skip-doctor.js'
import { formatError } from '../output.js'

function printDeleteHelp(): void {
  process.stdout.write(
    'Usage: vaultkeeper delete --name <name>\n\n' +
      'Options:\n' +
      '  --name <name>      Name of the secret to delete\n' +
      '  --skip-doctor      Skip doctor preflight checks\n' +
      '  -h, --help         Show this help message\n\n' +
      'Environment variables:\n' +
      '  VAULTKEEPER_SKIP_DOCTOR=1   Skip doctor preflight checks\n',
  )
}

export async function deleteCommand(args: string[]): Promise<number> {
  // Handle --help / -h before strict parseArgs.
  if (args.includes('--help') || args.includes('-h')) {
    printDeleteHelp()
    return 0
  }

  const { values } = parseArgs({
    args,
    options: {
      name: { type: 'string' },
      'skip-doctor': { type: 'boolean', default: false },
    },
    strict: true,
  })

  if (values.name === undefined) {
    process.stderr.write('Error: --name is required\n')
    process.stderr.write('Usage: vaultkeeper delete --name <name>\n')
    // Exit code 2: usage error (missing required flag)
    return 2
  }

  const skipDoctor = shouldSkipDoctor(values['skip-doctor'])

  try {
    // Delete via VaultKeeper, which resolves the first enabled backend from the
    // loaded config and forwards that backend's config (including `path`).
    const vault = await VaultKeeper.init({ skipDoctor })
    await vault.delete(values.name)
    process.stdout.write(`Secret "${values.name}" deleted.\n`)
    return 0
  } catch (err) {
    process.stderr.write(`${formatError(err)}\n`)
    return 1
  }
}
