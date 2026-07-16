import { parseArgs } from 'node:util'
import { VaultKeeper, defaultBackendType } from 'vaultkeeper'
import { shouldSkipDoctor } from '../skip-doctor.js'
import { formatError } from '../output.js'
import { CONFIG_DIR_HELP_OPTION, CONFIG_DIR_HELP_ENV } from '../config-dir.js'
import { configFileExists, noConfigMessage } from '../config-status.js'
import { SECRET_NAME_PATTERN, SECRET_NAME_RULE } from '../secret-name.js'

function printStoreHelp(): void {
  process.stdout.write(
    'Usage: echo "secret" | vaultkeeper store --name <name>\n\n' +
      'Options:\n' +
      // Derived from SECRET_NAME_RULE (the single source of truth for the
      // pattern's human description) so help and validation can't drift.
      `  --name <name>      Name to store the secret under; ${SECRET_NAME_RULE}\n` +
      '  --skip-doctor      Skip doctor preflight checks\n' +
      CONFIG_DIR_HELP_OPTION +
      '  -h, --help         Show this help message\n\n' +
      'Environment variables:\n' +
      '  VAULTKEEPER_SKIP_DOCTOR=1   Skip doctor preflight checks\n' +
      CONFIG_DIR_HELP_ENV,
  )
}

export async function storeCommand(args: string[], configDir: string): Promise<number> {
  // Handle --help / -h before parseArgs to avoid strict-mode rejection of -h.
  if (args.includes('--help') || args.includes('-h')) {
    printStoreHelp()
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
    // An unrecognized flag throws synchronously from parseArgs — convert it
    // to the same usage-error exit code as a missing/invalid flag value
    // (regression: issue #69, this previously propagated uncaught and
    // exited 1 via bin.ts's fatal-error handler instead of 2).
    if (err instanceof Error) {
      process.stderr.write(`Error: ${err.message}\n`)
    }
    process.stderr.write('Usage: echo "secret" | vaultkeeper store --name <name>\n')
    return 2
  }

  if (values.name === undefined) {
    process.stderr.write('Error: --name is required\n')
    process.stderr.write('Usage: echo "secret" | vaultkeeper store --name <name>\n')
    // Exit code 2: usage error (missing required flag)
    return 2
  }

  // Reject empty/whitespace-only (and otherwise invalid-character) names
  // with the same exit code and error style as a missing flag — previously
  // `store --name ""` reached VaultKeeper.store(), which threw a generic
  // VaultError with exit 1 instead of a usage error (issue #69).
  if (!SECRET_NAME_PATTERN.test(values.name)) {
    process.stderr.write(`Error: --name ${SECRET_NAME_RULE}\n`)
    process.stderr.write('Usage: echo "secret" | vaultkeeper store --name <name>\n')
    // Exit code 2: usage error (invalid flag value)
    return 2
  }

  const skipDoctor = shouldSkipDoctor(values['skip-doctor'])

  try {
    // Read secret from stdin
    const chunks: Buffer[] = []
    for await (const chunk of process.stdin) {
      if (chunk instanceof Buffer) {
        chunks.push(chunk)
      } else if (typeof chunk === 'string') {
        chunks.push(Buffer.from(chunk))
      } else {
        chunks.push(Buffer.from(String(chunk)))
      }
    }
    const secret = Buffer.concat(chunks).toString('utf8').trimEnd()

    if (secret.length === 0) {
      // Exit code 2, not 1: empty stdin is equivalent misuse to an empty or
      // missing `--name` above — both mean "no usable input was given" — and
      // must be reported the same way (regression: issue #118 exit-code
      // matrix normalization against the #69 taxonomy).
      process.stderr.write('Error: No secret provided on stdin\n')
      process.stderr.write('Usage: echo "secret" | vaultkeeper store --name <name>\n')
      return 2
    }

    // No-config story is uniform across store/delete/exec/config show/doctor
    // (issue #68): fall back to platform defaults and say so, rather than
    // silently defaulting.
    if (!(await configFileExists(configDir))) {
      process.stderr.write(noConfigMessage(defaultBackendType()))
    }

    // Store via VaultKeeper, which resolves the first enabled backend from the
    // loaded config and forwards that backend's config (including `path`).
    const vault = await VaultKeeper.init({ configDir, skipDoctor })
    await vault.store(values.name, secret)
    process.stdout.write(`Secret "${values.name}" stored successfully.\n`)
    return 0
  } catch (err) {
    process.stderr.write(`${formatError(err, configDir)}\n`)
    return 1
  }
}
