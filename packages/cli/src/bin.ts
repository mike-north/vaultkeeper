#!/usr/bin/env node
/**
 * CLI entry point for vaultkeeper.
 *
 * Each subcommand is lazy-loaded via dynamic import() to minimize startup
 * time — only the requested command's module (and its dependencies) is loaded.
 *
 * argv layout: [node, script, subcommand, ...commandArgs]
 * parseArgs consumes argv[2..] and extracts the subcommand as positionals[0].
 * commandArgs is argv[3..] — everything after the subcommand.
 *
 * Exit codes:
 *   0 — success
 *   1 — runtime / vault error
 *   2 — usage error (unknown command, missing required argument, bad flag)
 *
 * @internal
 */

import * as fs from 'node:fs'
import * as path from 'node:path'
import { fileURLToPath } from 'node:url'
import { parseArgs } from 'node:util'

// Read the package version at startup so --version doesn't need an async import.
// We read and parse the package.json synchronously to avoid a dynamic import()
// that would require top-level await or restructuring main().
function readPackageVersion(): string {
  try {
    const pkgPath = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../package.json')
    const raw: unknown = JSON.parse(fs.readFileSync(pkgPath, 'utf8'))
    if (raw !== null && typeof raw === 'object' && 'version' in raw && typeof raw.version === 'string') {
      return raw.version
    }
  } catch {
    // package.json absent or malformed — return sentinel
  }
  return '0.0.0'
}

const packageVersion = readPackageVersion()

// argv[2] is the first user-supplied token. Check it directly before
// parseArgs so that --version / -V (parsed as option values, not positionals)
// and --help / -h are handled without going through the switch.
const firstArg = process.argv[2]

const { positionals } = parseArgs({
  allowPositionals: true,
  strict: false,
})

const subcommand = positionals[0]
// argv[0]=node, argv[1]=script, argv[2]=subcommand, argv[3..]=commandArgs
const commandArgs = process.argv.slice(3)

function printHelp(): void {
  process.stdout.write(
    'Usage: vaultkeeper <command> [options]\n\n' +
      'Commands:\n' +
      '  exec         Run a command with a secret injected as an env var\n' +
      '  doctor       Run preflight checks\n' +
      '  approve      Pre-record a script hash in the TOFU manifest\n' +
      '  dev-mode     Toggle development mode for a script\n' +
      '  store        Store a secret (reads from stdin)\n' +
      '  delete       Delete a secret\n' +
      '  config       Manage configuration\n' +
      '  rotate-key   Rotate the encryption key\n' +
      '  revoke-key   Emergency key revocation\n',
  )
}

async function main(): Promise<number> {
  // Handle --version / -V before subcommand dispatch.
  // parseArgs treats these as option values (not positionals) with strict:false,
  // so we inspect argv[2] directly to detect them.
  if (firstArg === '--version' || firstArg === '-V') {
    process.stdout.write(`${packageVersion}\n`)
    return 0
  }

  // Handle --help / -h and no-argument invocations at the top level.
  if (firstArg === '--help' || firstArg === '-h' || subcommand === undefined) {
    printHelp()
    return 0
  }

  switch (subcommand) {
    case 'exec': {
      const { execCommand } = await import('./commands/exec.js')
      return execCommand(commandArgs)
    }
    case 'doctor': {
      const { doctorCommand } = await import('./commands/doctor.js')
      return doctorCommand(commandArgs)
    }
    case 'approve': {
      const { approveCommand } = await import('./commands/approve.js')
      return approveCommand(commandArgs)
    }
    case 'dev-mode': {
      const { devModeCommand } = await import('./commands/dev-mode.js')
      return devModeCommand(commandArgs)
    }
    case 'store': {
      const { storeCommand } = await import('./commands/store.js')
      return storeCommand(commandArgs)
    }
    case 'delete': {
      const { deleteCommand } = await import('./commands/delete.js')
      return deleteCommand(commandArgs)
    }
    case 'config': {
      const { configCommand } = await import('./commands/config.js')
      return configCommand(commandArgs)
    }
    case 'rotate-key': {
      const { rotateKeyCommand } = await import('./commands/rotate-key.js')
      return rotateKeyCommand(commandArgs)
    }
    case 'revoke-key': {
      const { revokeKeyCommand } = await import('./commands/revoke-key.js')
      return revokeKeyCommand(commandArgs)
    }
    default:
      process.stderr.write(`Unknown command: ${subcommand}\n`)
      printHelp()
      // Exit code 2: usage error (unknown command)
      return 2
  }
}

main()
  .then((code) => {
    process.exitCode = code
  })
  .catch((err: unknown) => {
    process.stderr.write(`Fatal: ${err instanceof Error ? err.message : String(err)}\n`)
    process.exitCode = 1
  })
