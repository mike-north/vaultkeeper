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
 * @internal
 */

import { parseArgs } from 'node:util'

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
      '  rotate-key   Rotate the encryption key\n',
  )
}

async function main(): Promise<number> {
  // [S1 fix] Handle --help and no-argument invocations
  if (subcommand === undefined || subcommand === '--help' || subcommand === '-h') {
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
    default:
      process.stderr.write(`Unknown command: ${subcommand}\n`)
      printHelp()
      return 1
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
