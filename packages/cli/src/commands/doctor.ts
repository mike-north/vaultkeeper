import { VaultKeeper, loadConfig } from 'vaultkeeper'
import { formatError } from '../output.js'
import { CONFIG_DIR_HELP_OPTION, CONFIG_DIR_HELP_ENV } from '../config-dir.js'

function printDoctorHelp(): void {
  process.stdout.write(
    'Usage: vaultkeeper doctor\n\n' +
      'Run preflight checks to verify the vault is correctly configured\n' +
      'and all required dependencies are available.\n\n' +
      'Options:\n' +
      CONFIG_DIR_HELP_OPTION +
      '  -h, --help   Show this help message\n\n' +
      'Environment variables:\n' +
      CONFIG_DIR_HELP_ENV,
  )
}

export async function doctorCommand(args: string[], configDir: string): Promise<number> {
  if (args.includes('--help') || args.includes('-h')) {
    printDoctorHelp()
    return 0
  }

  try {
    // Scope checks to the backends configured under configDir, so doctor
    // reflects the same config the other commands will read/write.
    const config = await loadConfig(configDir)
    const result = await VaultKeeper.doctor({ backends: config.backends })

    for (const check of result.checks) {
      const icon = check.status === 'ok' ? '✓' : '✗'
      const version = check.version !== undefined ? ` (${check.version})` : ''
      const reason = check.reason !== undefined ? ` — ${check.reason}` : ''
      process.stdout.write(`  ${icon} ${check.name}${version}${reason}\n`)
    }

    if (result.warnings.length > 0) {
      process.stdout.write('\nWarnings:\n')
      for (const warning of result.warnings) {
        process.stdout.write(`  ⚠ ${warning}\n`)
      }
    }

    if (result.ready) {
      process.stdout.write('\nSystem ready.\n')
      return 0
    }

    process.stdout.write('\nNext steps:\n')
    for (const step of result.nextSteps) {
      process.stdout.write(`  → ${step}\n`)
    }
    return 1
  } catch (err) {
    process.stderr.write(`${formatError(err)}\n`)
    return 1
  }
}
