import { VaultKeeper } from 'vaultkeeper'
import { formatError } from '../output.js'

function printRevokeKeyHelp(): void {
  process.stdout.write(
    'Usage: vaultkeeper revoke-key\n\n' +
      'Emergency revocation of the active encryption key. All tokens signed\n' +
      'with the revoked key become immediately invalid.\n\n' +
      'Options:\n' +
      '  -h, --help   Show this help message\n',
  )
}

export async function revokeKeyCommand(args: string[]): Promise<number> {
  if (args.includes('--help') || args.includes('-h')) {
    printRevokeKeyHelp()
    return 0
  }

  try {
    const vault = await VaultKeeper.init()
    await vault.revokeKey()
    process.stdout.write('Key revoked successfully.\n')
    return 0
  } catch (err) {
    process.stderr.write(`${formatError(err)}\n`)
    return 1
  }
}
