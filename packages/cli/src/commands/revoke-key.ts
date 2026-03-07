import { parseArgs } from 'node:util'
import { VaultKeeper } from 'vaultkeeper'
import { shouldSkipDoctor } from '../skip-doctor.js'
import { formatError } from '../output.js'

function printRevokeKeyHelp(): void {
  process.stdout.write(
    'Usage: vaultkeeper revoke-key\n\n' +
      'Emergency revocation of the active encryption key. All tokens signed\n' +
      'with the revoked key become immediately invalid.\n\n' +
      'Options:\n' +
      '  --skip-doctor          Skip doctor preflight checks\n' +
      '  -h, --help             Show this help message\n\n' +
      'Environment variables:\n' +
      '  VAULTKEEPER_SKIP_DOCTOR=1   Skip doctor preflight checks\n',
  )
}

export async function revokeKeyCommand(args: string[]): Promise<number> {
  if (args.includes('--help') || args.includes('-h')) {
    printRevokeKeyHelp()
    return 0
  }

  const options = {
    'skip-doctor': { type: 'boolean' as const, default: false },
  }

  let skipDoctorFlag: boolean
  try {
    const parsed = parseArgs({ args, options, strict: true })
    skipDoctorFlag = parsed.values['skip-doctor']
  } catch (err) {
    if (err instanceof Error) {
      process.stderr.write(`Error: ${err.message}\n`)
    }
    printRevokeKeyHelp()
    return 2
  }

  const skipDoctor = shouldSkipDoctor(skipDoctorFlag)

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
