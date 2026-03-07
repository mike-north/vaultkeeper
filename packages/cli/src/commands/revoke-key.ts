import { parseArgs } from 'node:util'
import { VaultKeeper } from 'vaultkeeper'
import { formatError } from '../output.js'

function printRevokeKeyHelp(): void {
  process.stdout.write(
    'Usage: vaultkeeper revoke-key\n\n' +
      'Emergency revocation of the active encryption key. All tokens signed\n' +
      'with the revoked key become immediately invalid.\n\n' +
      'Options:\n' +
      '  --skip-doctor      Skip preflight dependency checks\n' +
      '  -h, --help         Show this help message\n' +
      '\nEnvironment:\n' +
      '  VAULTKEEPER_SKIP_DOCTOR=1  Skip preflight dependency checks\n',
  )
}

export async function revokeKeyCommand(args: string[]): Promise<number> {
  if (args.includes('--help') || args.includes('-h')) {
    printRevokeKeyHelp()
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
    await vault.revokeKey()
    process.stdout.write('Key revoked successfully.\n')
    return 0
  } catch (err) {
    process.stderr.write(`${formatError(err)}\n`)
    return 1
  }
}
