import { parseArgs } from 'node:util'
import { BackendRegistry, VaultKeeper } from 'vaultkeeper'
import { formatError } from '../output.js'

export async function deleteCommand(args: string[]): Promise<number> {
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
    return 1
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
