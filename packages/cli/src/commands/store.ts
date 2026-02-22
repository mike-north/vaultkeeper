import { parseArgs } from 'node:util'
import { BackendRegistry, VaultKeeper } from 'vaultkeeper'
import { formatError } from '../output.js'

export async function storeCommand(args: string[]): Promise<number> {
  const { values } = parseArgs({
    args,
    options: {
      name: { type: 'string' },
    },
    strict: true,
  })

  if (values.name === undefined) {
    process.stderr.write('Error: --name is required\n')
    process.stderr.write('Usage: echo "secret" | vaultkeeper store --name <name>\n')
    return 1
  }

  try {
    // Read secret from stdin
    const chunks: Buffer[] = []
    for await (const chunk of process.stdin) {
      if (chunk instanceof Buffer) {
        chunks.push(chunk)
      } else if (typeof chunk === 'string') {
        chunks.push(Buffer.from(chunk))
      } else {
        chunks.push(Buffer.from(String(chunk)))
      }
    }
    const secret = Buffer.concat(chunks).toString('utf8').trimEnd()

    if (secret.length === 0) {
      process.stderr.write('Error: No secret provided on stdin\n')
      return 1
    }

    // Initialize vault to run doctor checks and register backends.
    // The return value is not used — init() is called for its side effects
    // (doctor checks and backend registration). TODO: VaultKeeper should expose
    // a public store() method; until then we use BackendRegistry.create() with
    // the config-resolved type.
    await VaultKeeper.init()
    const types = BackendRegistry.getTypes()
    const firstType = types[0]
    if (firstType === undefined) {
      process.stderr.write('Error: No backends available\n')
      return 1
    }

    const backend = BackendRegistry.create(firstType)
    await backend.store(values.name, secret)
    process.stdout.write(`Secret "${values.name}" stored successfully.\n`)
    return 0
  } catch (err) {
    process.stderr.write(`${formatError(err)}\n`)
    return 1
  }
}
