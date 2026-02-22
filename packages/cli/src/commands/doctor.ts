import { VaultKeeper } from 'vaultkeeper'
import { formatError } from '../output.js'

export async function doctorCommand(_args: string[]): Promise<number> {
  try {
    const result = await VaultKeeper.doctor()

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
