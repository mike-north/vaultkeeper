import { parseArgs } from 'node:util'
import { VaultKeeper } from 'vaultkeeper'
import { shouldSkipDoctor } from '../skip-doctor.js'
import { formatError } from '../output.js'
import { CONFIG_DIR_HELP_OPTION, CONFIG_DIR_HELP_ENV } from '../config-dir.js'

function printRotateKeyHelp(): void {
  process.stdout.write(
    'Usage: vaultkeeper rotate-key\n\n' +
      'Rotate the active encryption key. Secrets encrypted with the previous\n' +
      'key remain readable during the configured grace period.\n\n' +
      'Options:\n' +
      '  --skip-doctor          Skip doctor preflight checks\n' +
      CONFIG_DIR_HELP_OPTION +
      '  -h, --help             Show this help message\n\n' +
      'Environment variables:\n' +
      '  VAULTKEEPER_SKIP_DOCTOR=1   Skip doctor preflight checks\n' +
      CONFIG_DIR_HELP_ENV,
  )
}

export async function rotateKeyCommand(args: string[], configDir: string): Promise<number> {
  if (args.includes('--help') || args.includes('-h')) {
    printRotateKeyHelp()
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
    printRotateKeyHelp()
    return 2
  }

  const skipDoctor = shouldSkipDoctor(skipDoctorFlag)

  try {
    const vault = await VaultKeeper.init({ configDir, skipDoctor })
    await vault.rotateKey()
    process.stdout.write('Key rotated successfully.\n')
    return 0
  } catch (err) {
    process.stderr.write(`${formatError(err, configDir)}\n`)
    return 1
  }
}
