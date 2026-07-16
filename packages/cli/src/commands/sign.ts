import { parseArgs } from 'node:util'
import { VaultKeeper, defaultBackendType } from 'vaultkeeper'
import { shouldSkipDoctor } from '../skip-doctor.js'
import { formatError } from '../output.js'
import { CONFIG_DIR_HELP_OPTION, CONFIG_DIR_HELP_ENV } from '../config-dir.js'
import { configFileExists, noConfigMessage } from '../config-status.js'
import { SECRET_NAME_PATTERN, SECRET_NAME_RULE } from '../secret-name.js'
import { readStdinBytes } from '../stdin.js'

function printSignHelp(): void {
  process.stdout.write(
    'Usage: printf %s "$PAYLOAD" | vaultkeeper sign --name <name>\n\n' +
      'Reads all of stdin as the payload to sign and writes exactly the detached\n' +
      'signature to stdout (nothing else) — human status goes to stderr, so the\n' +
      'signature is safe to redirect (`... | vaultkeeper sign --name k > sig`).\n\n' +
      'Signature format (verifiable by any standard JOSE library):\n' +
      '  algorithm  = EdDSA (Ed25519)\n' +
      '  encoding   = base64url, no padding (RFC 7515)\n' +
      '  detachment = detached payload, RFC 7797 b64:false, crit:["b64"]\n' +
      '  output     = compact JWS <protected>..<signature>\n\n' +
      'Options:\n' +
      '  --name <name>      Signing key to use. ' +
      SECRET_NAME_RULE +
      '\n' +
      '  --skip-doctor      Skip doctor preflight checks\n' +
      CONFIG_DIR_HELP_OPTION +
      '  -h, --help         Show this help message\n\n' +
      'Environment variables:\n' +
      '  VAULTKEEPER_SKIP_DOCTOR=1   Skip doctor preflight checks\n' +
      CONFIG_DIR_HELP_ENV,
  )
}

export async function signCommand(args: string[], configDir: string): Promise<number> {
  if (args.includes('--help') || args.includes('-h')) {
    printSignHelp()
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
    if (err instanceof Error) {
      process.stderr.write(`Error: ${err.message}\n`)
    }
    process.stderr.write('Usage: printf %s "$PAYLOAD" | vaultkeeper sign --name <name>\n')
    return 2
  }

  if (values.name === undefined || !SECRET_NAME_PATTERN.test(values.name)) {
    process.stderr.write(`Error: --name is required and ${SECRET_NAME_RULE}\n`)
    return 2
  }
  const name = values.name
  const skipDoctor = shouldSkipDoctor(values['skip-doctor'])

  try {
    // Inside the try so any readStdinBytes() failure (it guards against stdin
    // being in string mode) flows through this command's error handling rather
    // than the top-level fatal handler.
    const payload = await readStdinBytes()
    if (payload.length === 0) {
      process.stderr.write('Error: no payload provided on stdin\n')
      // Exit code 2: usage error (empty stdin).
      return 2
    }

    if (!(await configFileExists(configDir))) {
      process.stderr.write(noConfigMessage(defaultBackendType()))
    }
    const vault = await VaultKeeper.init({ configDir, skipDoctor })
    const token = await vault.authorizeSigningKey(name)
    const { result } = await vault.sign(token, { payload })
    // Exactly the detached signature on stdout, terminated with a single
    // newline. Nothing else — status already went to stderr above.
    process.stdout.write(`${result.jws}\n`)
    return 0
  } catch (err) {
    process.stderr.write(`${formatError(err, configDir)}\n`)
    return 1
  }
}
