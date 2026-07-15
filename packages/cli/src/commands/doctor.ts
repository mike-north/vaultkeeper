import { parseArgs } from 'node:util'
import { VaultKeeper, defaultBackendType } from 'vaultkeeper'
import { formatError } from '../output.js'
import { CONFIG_DIR_HELP_OPTION, CONFIG_DIR_HELP_ENV } from '../config-dir.js'
import { configFileExists, noConfigMessage } from '../config-status.js'

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

  // doctor takes no flags of its own (--config-dir is stripped by bin.ts
  // before dispatch). Previously any unrecognized flag was silently
  // ignored — `doctor --bogus` ran the real checks and could exit 0
  // (regression: issue #69) instead of failing as a usage error.
  try {
    parseArgs({ args, strict: true })
  } catch (err) {
    if (err instanceof Error) {
      process.stderr.write(`Error: ${err.message}\n`)
    }
    process.stderr.write('Usage: vaultkeeper doctor\n')
    return 2
  }

  try {
    // Scope checks to the config under configDir: runDoctor loads and
    // validates it itself (via `configDir`), so a present-but-invalid config
    // file surfaces as a failing "config" check rather than being silently
    // skipped or crashing doctor outright (issue #68).
    if (!(await configFileExists(configDir))) {
      process.stderr.write(noConfigMessage(defaultBackendType()))
    }
    const result = await VaultKeeper.doctor({ configDir })

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
