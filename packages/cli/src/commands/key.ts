import { parseArgs } from 'node:util'
import { VaultKeeper, defaultBackendType } from 'vaultkeeper'
import type { SigningAlgorithm } from 'vaultkeeper'
import { shouldSkipDoctor } from '../skip-doctor.js'
import { formatError } from '../output.js'
import { CONFIG_DIR_HELP_OPTION, CONFIG_DIR_HELP_ENV } from '../config-dir.js'
import { configFileExists, noConfigMessage } from '../config-status.js'
import { SECRET_NAME_PATTERN, SECRET_NAME_RULE } from '../secret-name.js'

/**
 * Accepted `--type` values mapped to their strict JOSE algorithm identifier.
 * Unknown types are rejected (exit 2) — there is never a silent default.
 */
const KEY_TYPES: Record<string, SigningAlgorithm> = {
  ed25519: 'EdDSA',
}

function printKeyHelp(): void {
  process.stdout.write(
    'Usage: vaultkeeper key <create|export> --name <name> [options]\n\n' +
      'Subcommands:\n' +
      '  create   Provision a signing keypair in the active backend\n' +
      '  export   Print the SPKI PEM public key to stdout\n\n' +
      'Options:\n' +
      '  --name <name>      Name of the signing key. ' +
      SECRET_NAME_RULE +
      '\n' +
      '  --type <type>      Key type for `create` (required). Supported: ed25519\n' +
      '  --skip-doctor      Skip doctor preflight checks\n' +
      CONFIG_DIR_HELP_OPTION +
      '  -h, --help         Show this help message\n\n' +
      'Signing keys are a distinct resource from secrets: private key material\n' +
      'never leaves the backend and is never readable as a secret.\n\n' +
      'Environment variables:\n' +
      '  VAULTKEEPER_SKIP_DOCTOR=1   Skip doctor preflight checks\n' +
      CONFIG_DIR_HELP_ENV,
  )
}

export async function keyCommand(args: string[], configDir: string): Promise<number> {
  if (args.includes('--help') || args.includes('-h')) {
    printKeyHelp()
    return 0
  }

  const subcommand = args[0]
  if (subcommand !== 'create' && subcommand !== 'export') {
    if (subcommand === undefined) {
      process.stderr.write('Error: missing subcommand (expected `create` or `export`)\n')
    } else {
      process.stderr.write(`Error: unknown key subcommand '${subcommand}'\n`)
    }
    process.stderr.write('Usage: vaultkeeper key <create|export> --name <name> [options]\n')
    return 2
  }

  let values: { name?: string; type?: string; 'skip-doctor': boolean }
  try {
    ;({ values } = parseArgs({
      args: args.slice(1),
      options: {
        name: { type: 'string' },
        type: { type: 'string' },
        'skip-doctor': { type: 'boolean', default: false },
      },
      strict: true,
    }))
  } catch (err) {
    if (err instanceof Error) {
      process.stderr.write(`Error: ${err.message}\n`)
    }
    process.stderr.write('Usage: vaultkeeper key <create|export> --name <name> [options]\n')
    return 2
  }

  if (values.name === undefined || !SECRET_NAME_PATTERN.test(values.name)) {
    process.stderr.write(`Error: --name is required and ${SECRET_NAME_RULE}\n`)
    return 2
  }
  const name = values.name

  // `create` requires a valid --type; `export` ignores it.
  let algorithm: SigningAlgorithm | undefined
  if (subcommand === 'create') {
    if (values.type === undefined) {
      process.stderr.write('Error: --type is required for `key create` (supported: ed25519)\n')
      return 2
    }
    const mapped = KEY_TYPES[values.type]
    if (mapped === undefined) {
      process.stderr.write(
        `Error: unknown --type '${values.type}'. Supported: ${Object.keys(KEY_TYPES).join(', ')}\n`,
      )
      return 2
    }
    algorithm = mapped
  }

  const skipDoctor = shouldSkipDoctor(values['skip-doctor'])

  try {
    if (!(await configFileExists(configDir))) {
      process.stderr.write(noConfigMessage(defaultBackendType()))
    }
    const vault = await VaultKeeper.init({ configDir, skipDoctor })

    if (subcommand === 'create') {
      // algorithm is defined here (set above for the create branch).
      const pub = await vault.createSigningKey(name, algorithm ?? 'EdDSA')
      process.stderr.write(`Signing key "${name}" created (kid ${pub.kid}).\n`)
      return 0
    }

    const pub = await vault.exportPublicKey(name)
    process.stdout.write(
      pub.publicKeyPem.endsWith('\n') ? pub.publicKeyPem : `${pub.publicKeyPem}\n`,
    )
    return 0
  } catch (err) {
    process.stderr.write(`${formatError(err, configDir)}\n`)
    return 1
  }
}
