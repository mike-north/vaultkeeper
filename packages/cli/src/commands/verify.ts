import * as fs from 'node:fs/promises'
import { parseArgs } from 'node:util'
import { VaultKeeper, InvalidKeyMaterialError } from 'vaultkeeper'
import { readStdinBytes } from '../stdin.js'

/**
 * Exit codes for `verify` (a deliberate, documented exception to the standard
 * 0/1/2 taxonomy — precedent: `gpg --verify`, `ssh-keygen -Y verify`):
 *
 *   0 — signature valid
 *   1 — operational fault (unreadable file, unparseable public key)
 *   2 — usage error (missing flags, empty stdin)
 *   3 — signature did NOT verify (tampered payload, wrong key, malformed JWS)
 *
 * Exit 3 lets a script distinguish "the signature is bad" from "the tool broke"
 * without parsing stderr. `verify` never uses 1 for a bad signature.
 */

function printVerifyHelp(): void {
  process.stdout.write(
    'Usage: vaultkeeper verify --public-key <pem-path> --signature <sig-path> < payload\n\n' +
      'Verifies a detached signature fully offline: no config, no backend, no key\n' +
      'store — only the public key, the payload on stdin, and the signature file.\n\n' +
      'Signature format (any standard JOSE library can produce a compatible one):\n' +
      '  algorithm  = EdDSA (Ed25519)\n' +
      '  encoding   = base64url, no padding (RFC 7515)\n' +
      '  detachment = detached payload, RFC 7797 b64:false, crit:["b64"]\n\n' +
      'Options:\n' +
      '  --public-key <path>   Path to the SPKI PEM public key\n' +
      '  --signature <path>    Path to the detached compact JWS signature\n' +
      '  -h, --help            Show this help message\n\n' +
      'Exit codes:\n' +
      '  0  signature valid\n' +
      '  1  operational fault (unreadable file, unparseable public key)\n' +
      '  2  usage error (missing flags, empty stdin)\n' +
      '  3  signature did not verify (tampered payload, wrong key, malformed JWS)\n',
  )
}

/** Read a file, mapping any I/O failure to an operational-fault (exit 1) marker. */
async function readFileForVerify(filePath: string, label: string): Promise<string> {
  try {
    return await fs.readFile(filePath, 'utf8')
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err)
    throw new OperationalFault(`Failed to read ${label} at ${filePath}: ${detail}`)
  }
}

/** Marker for an operational fault that must map to exit 1. */
class OperationalFault extends Error {}

export async function verifyCommand(args: string[]): Promise<number> {
  if (args.includes('--help') || args.includes('-h')) {
    printVerifyHelp()
    return 0
  }

  let values: { 'public-key'?: string; signature?: string }
  try {
    ;({ values } = parseArgs({
      args,
      options: {
        'public-key': { type: 'string' },
        signature: { type: 'string' },
      },
      strict: true,
    }))
  } catch (err) {
    if (err instanceof Error) {
      process.stderr.write(`Error: ${err.message}\n`)
    }
    process.stderr.write(
      'Usage: vaultkeeper verify --public-key <pem-path> --signature <sig-path> < payload\n',
    )
    return 2
  }

  const publicKeyPath = values['public-key']
  const signaturePath = values.signature
  if (publicKeyPath === undefined || signaturePath === undefined) {
    process.stderr.write('Error: --public-key and --signature are both required\n')
    return 2
  }

  const payload = await readStdinBytes()
  if (payload.length === 0) {
    process.stderr.write('Error: no payload provided on stdin\n')
    // Exit code 2: usage error (empty stdin).
    return 2
  }

  try {
    const publicKey = await readFileForVerify(publicKeyPath, 'public key')
    const jws = await readFileForVerify(signaturePath, 'signature')

    const valid = await VaultKeeper.verify({ payload, jws, publicKey })
    if (valid) {
      process.stderr.write('Signature valid.\n')
      return 0
    }
    process.stderr.write('Signature did not verify.\n')
    // Exit code 3: the signature is bad (tampered, wrong key, or malformed JWS).
    return 3
  } catch (err) {
    if (err instanceof OperationalFault || err instanceof InvalidKeyMaterialError) {
      // Operational fault: unreadable file or unparseable public key.
      process.stderr.write(`Error: ${err.message}\n`)
      return 1
    }
    process.stderr.write(`Error: ${err instanceof Error ? err.message : String(err)}\n`)
    return 1
  }
}
