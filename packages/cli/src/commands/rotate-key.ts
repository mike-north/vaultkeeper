import { VaultKeeper } from 'vaultkeeper'
import { formatError } from '../output.js'

function printRotateKeyHelp(): void {
  process.stdout.write(
    'Usage: vaultkeeper rotate-key\n\n' +
      'Rotate the active encryption key. Secrets encrypted with the previous\n' +
      'key remain readable during the configured grace period.\n\n' +
      'Options:\n' +
      '  -h, --help   Show this help message\n',
  )
}

export async function rotateKeyCommand(args: string[]): Promise<number> {
  if (args.includes('--help') || args.includes('-h')) {
    printRotateKeyHelp()
    return 0
  }

  try {
    const vault = await VaultKeeper.init()
    await vault.rotateKey()
    process.stdout.write('Key rotated successfully.\n')
    return 0
  } catch (err) {
    process.stderr.write(`${formatError(err)}\n`)
    return 1
  }
}
