import { parseArgs } from 'node:util'
import { VaultKeeper } from 'vaultkeeper'
import { formatError } from '../output.js'

function printRotateKeyHelp(): void {
  process.stdout.write(
    'Usage: vaultkeeper rotate-key\n\n' +
      'Rotate the active encryption key. Secrets encrypted with the previous\n' +
      'key remain readable during the configured grace period.\n\n' +
      'Options:\n' +
      '  --skip-doctor      Skip preflight dependency checks\n' +
      '  -h, --help         Show this help message\n' +
      '\nEnvironment:\n' +
      '  VAULTKEEPER_SKIP_DOCTOR=1  Skip preflight dependency checks\n',
  )
}

export async function rotateKeyCommand(args: string[]): Promise<number> {
  if (args.includes('--help') || args.includes('-h')) {
    printRotateKeyHelp()
    return 0
  }

  const { values } = parseArgs({
    args,
    options: {
      'skip-doctor': { type: 'boolean', default: false },
    },
    strict: true,
  })

  const skipDoctor: boolean =
    values['skip-doctor'] || process.env.VAULTKEEPER_SKIP_DOCTOR === '1'

  try {
    const vault = await VaultKeeper.init({ skipDoctor })
    await vault.rotateKey()
    process.stdout.write('Key rotated successfully.\n')
    return 0
  } catch (err) {
    process.stderr.write(`${formatError(err)}\n`)
    return 1
  }
}
