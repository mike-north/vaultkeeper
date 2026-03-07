import { parseArgs } from 'node:util'
import { BackendRegistry, VaultKeeper } from 'vaultkeeper'
import { formatError } from '../output.js'

function printDeleteHelp(): void {
  process.stdout.write(
    'Usage: vaultkeeper delete --name <name>\n\n' +
      'Options:\n' +
      '  --name <name>   Name of the secret to delete\n' +
      '  -h, --help      Show this help message\n',
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
    },
    strict: true,
  })

  if (values.name === undefined) {
    process.stderr.write('Error: --name is required\n')
    process.stderr.write('Usage: vaultkeeper delete --name <name>\n')
    // Exit code 2: usage error (missing required flag)
    return 2
  }

  try {
    // Initialize vault to ensure backends are registered and doctor passes
    await VaultKeeper.init()

    const types = BackendRegistry.getTypes()
    const firstType = types[0]
    if (firstType === undefined) {
      process.stderr.write('Error: No backends available\n')
      return 1
    }

    const backend = BackendRegistry.create(firstType)
    await backend.delete(values.name)
    process.stdout.write(`Secret "${values.name}" deleted.\n`)
    return 0
  } catch (err) {
    process.stderr.write(`${formatError(err)}\n`)
    return 1
  }
}
