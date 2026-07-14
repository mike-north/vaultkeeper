import { parseArgs } from 'node:util'
import { VaultKeeper, platformDefaultBackendType } from 'vaultkeeper'
import { shouldSkipDoctor } from '../skip-doctor.js'
import { formatError } from '../output.js'
import { CONFIG_DIR_HELP_OPTION, CONFIG_DIR_HELP_ENV } from '../config-dir.js'
import { configFileExists, noConfigMessage } from '../config-status.js'

function printStoreHelp(): void {
  process.stdout.write(
    'Usage: echo "secret" | vaultkeeper store --name <name>\n\n' +
      'Options:\n' +
      '  --name <name>      Name to store the secret under\n' +
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

  const { values } = parseArgs({
    args,
    options: {
      name: { type: 'string' },
      'skip-doctor': { type: 'boolean', default: false },
    },
    strict: true,
  })

  if (values.name === undefined) {
    process.stderr.write('Error: --name is required\n')
    process.stderr.write('Usage: echo "secret" | vaultkeeper store --name <name>\n')
    // Exit code 2: usage error (missing required flag)
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
      process.stderr.write('Error: No secret provided on stdin\n')
      return 1
    }

    // No-config story is uniform across store/delete/exec/config show/doctor
    // (issue #68): fall back to platform defaults and say so, rather than
    // silently defaulting.
    if (!(await configFileExists(configDir))) {
      process.stderr.write(noConfigMessage(platformDefaultBackendType()))
    }

    // Store via VaultKeeper, which resolves the first enabled backend from the
    // loaded config and forwards that backend's config (including `path`).
    const vault = await VaultKeeper.init({ configDir, skipDoctor })
    await vault.store(values.name, secret)
    process.stdout.write(`Secret "${values.name}" stored successfully.\n`)
    return 0
  } catch (err) {
    process.stderr.write(`${formatError(err)}\n`)
    return 1
  }
}
