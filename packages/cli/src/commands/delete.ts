import { parseArgs } from 'node:util'
import { VaultKeeper, SecretNotFoundError, defaultBackendType } from 'vaultkeeper'
import { shouldSkipDoctor } from '../skip-doctor.js'
import { formatError, secretNotFoundMessage } from '../output.js'
import { CONFIG_DIR_HELP_OPTION, CONFIG_DIR_HELP_ENV } from '../config-dir.js'
import { configFileExists, noConfigMessage } from '../config-status.js'

// Same character policy as `store --name` (see store.ts) — keep in sync.
const SECRET_NAME_PATTERN = /^[A-Za-z0-9._/-]+$/

function printDeleteHelp(): void {
  process.stdout.write(
    'Usage: vaultkeeper delete --name <name>\n\n' +
      'Options:\n' +
      '  --name <name>      Name of the secret to delete. Must be non-empty\n' +
      '                     and contain only letters, digits, and . _ - /\n' +
      '  --skip-doctor      Skip doctor preflight checks\n' +
      CONFIG_DIR_HELP_OPTION +
      '  -h, --help         Show this help message\n\n' +
      'Environment variables:\n' +
      '  VAULTKEEPER_SKIP_DOCTOR=1   Skip doctor preflight checks\n' +
      CONFIG_DIR_HELP_ENV,
  )
}

export async function deleteCommand(args: string[], configDir: string): Promise<number> {
  // Handle --help / -h before strict parseArgs.
  if (args.includes('--help') || args.includes('-h')) {
    printDeleteHelp()
    return 0
  }

  let values: { name?: string; 'skip-doctor': boolean }
  try {
    ;({ values } = parseArgs({
      args,
      options: {
        name: { type: 'string' },
        'skip-doctor': { type: 'boolean', default: false },
      },
      strict: true,
    }))
  } catch (err) {
    // Regression: issue #69 — an unrecognized flag previously propagated
    // uncaught and exited 1 via bin.ts's fatal-error handler instead of the
    // usage-error exit code 2.
    if (err instanceof Error) {
      process.stderr.write(`Error: ${err.message}\n`)
    }
    process.stderr.write('Usage: vaultkeeper delete --name <name>\n')
    return 2
  }

  if (values.name === undefined) {
    process.stderr.write('Error: --name is required\n')
    process.stderr.write('Usage: vaultkeeper delete --name <name>\n')
    // Exit code 2: usage error (missing required flag)
    return 2
  }

  // Reject empty/whitespace-only (and otherwise invalid-character) names
  // with the same exit code and error style as a missing flag — same
  // consistency fix as `store --name` (issue #69).
  if (!SECRET_NAME_PATTERN.test(values.name)) {
    process.stderr.write(
      'Error: --name must be non-empty and contain only letters, digits, and . _ - /\n',
    )
    process.stderr.write('Usage: vaultkeeper delete --name <name>\n')
    // Exit code 2: usage error (invalid flag value)
    return 2
  }

  const skipDoctor = shouldSkipDoctor(values['skip-doctor'])

  try {
    // No-config story is uniform across store/delete/exec/config show/doctor
    // (issue #68): fall back to platform defaults and say so, rather than
    // silently defaulting.
    if (!(await configFileExists(configDir))) {
      process.stderr.write(noConfigMessage(defaultBackendType()))
    }

    // Delete via VaultKeeper, which resolves the first enabled backend from the
    // loaded config and forwards that backend's config (including `path`).
    const vault = await VaultKeeper.init({ configDir, skipDoctor })

    try {
      await vault.delete(values.name)
    } catch (deleteErr) {
      // Every backend's delete() throws SecretNotFoundError for a missing
      // secret, but each words it differently (e.g. the file backend's
      // "Secret not found in file store: x" vs exec's own wording). Catching
      // here — rather than a separate secretExists() pre-check — is the
      // single source of truth for this normalization: it also covers the
      // secret being deleted between any check and this call (issue #118
      // review), which a pre-check alone cannot.
      if (deleteErr instanceof SecretNotFoundError) {
        throw new SecretNotFoundError(
          secretNotFoundMessage(values.name, vault.activeBackendType, 'delete'),
        )
      }
      throw deleteErr
    }
    process.stdout.write(`Secret "${values.name}" deleted.\n`)
    return 0
  } catch (err) {
    process.stderr.write(`${formatError(err, configDir)}\n`)
    return 1
  }
}
