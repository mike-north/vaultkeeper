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
 * Exit-code convention:
 *   0 — success
 *   1 — a valid invocation that failed at runtime (e.g. SecretNotFoundError)
 *   2 — a bad invocation: usage / argument-validation error. Covers an unknown
 *       command, an unknown top-level flag, a missing/invalid required
 *       argument, empty stdin for `store`, and a bare invocation with no
 *       subcommand (which prints usage to stderr rather than exiting 0, so
 *       `vaultkeeper && next_step` does not proceed as if it succeeded).
 *
 * @internal
 */

import * as fs from 'node:fs'
import * as path from 'node:path'
import { fileURLToPath } from 'node:url'
import { parseArgs } from 'node:util'
import {
  extractConfigDirFlag,
  resolveConfigDir,
  CONFIG_DIR_HELP_OPTION,
  CONFIG_DIR_HELP_ENV,
} from './config-dir.js'

// Read the package version at startup so --version doesn't need an async import.
// We read and parse the package.json synchronously to avoid a dynamic import()
// that would require top-level await or restructuring main().
function readPackageVersion(): string {
  try {
    const pkgPath = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../package.json')
    const raw: unknown = JSON.parse(fs.readFileSync(pkgPath, 'utf8'))
    if (
      raw !== null &&
      typeof raw === 'object' &&
      'version' in raw &&
      typeof raw.version === 'string'
    ) {
      return raw.version
    }
  } catch {
    // package.json absent or malformed — return sentinel
  }
  return '0.0.0'
}

const packageVersion = readPackageVersion()

// The global --config-dir flag may appear anywhere before the subcommand's
// own `--` separator (if any), so it is extracted from the full argv up
// front — before subcommand/positional detection — and stripped from the
// args forwarded to the subcommand.
let configDirFlag: string | undefined
let filteredArgv: string[]
let configDirFlagError: string | undefined
try {
  const extracted = extractConfigDirFlag(process.argv.slice(2))
  configDirFlag = extracted.configDir
  filteredArgv = extracted.rest
} catch (err) {
  configDirFlagError = err instanceof Error ? err.message : String(err)
  filteredArgv = []
}

// The first user-supplied token (after --config-dir extraction). Check it
// directly before parseArgs so that --version / -V (parsed as option values,
// not positionals) and --help / -h are handled without going through the switch.
const firstArg = filteredArgv[0]

const { positionals } = parseArgs({
  args: filteredArgv,
  allowPositionals: true,
  strict: false,
})

const subcommand = positionals[0]
const commandArgs = filteredArgv.slice(1)

function printHelp(stream: NodeJS.WritableStream = process.stdout): void {
  stream.write(
    'Usage: vaultkeeper [--config-dir <path>] <command> [options]\n\n' +
      'Commands:\n' +
      '  exec         Run a command with a secret injected as an env var\n' +
      '  doctor       Run preflight checks\n' +
      '  approve      Pre-record a script hash in the TOFU manifest\n' +
      '  dev-mode     Toggle development mode for a script\n' +
      '  store        Store a secret (reads from stdin)\n' +
      '  delete       Delete a secret\n' +
      '  config       Manage configuration\n' +
      '  rotate-key   Rotate the encryption key\n' +
      '  revoke-key   Emergency key revocation\n\n' +
      'Global options:\n' +
      CONFIG_DIR_HELP_OPTION +
      '\n' +
      'Environment variables:\n' +
      CONFIG_DIR_HELP_ENV,
  )
}

async function main(): Promise<number> {
  if (configDirFlagError !== undefined) {
    process.stderr.write(`Error: ${configDirFlagError}\n`)
    // Exit code 2: usage error (--config-dir given without a value)
    return 2
  }

  // Handle --version / -V before subcommand dispatch.
  // parseArgs treats these as option values (not positionals) with strict:false,
  // so we inspect the first filtered token directly to detect them.
  if (firstArg === '--version' || firstArg === '-V') {
    process.stdout.write(`${packageVersion}\n`)
    return 0
  }

  // An explicit --help / -h is a successful request for usage: print to
  // stdout and exit 0.
  if (firstArg === '--help' || firstArg === '-h') {
    printHelp()
    return 0
  }

  // A bare invocation (no arguments at all) is a usage error, not success:
  // print usage to stderr and exit 2 so that `vaultkeeper && next_step` does
  // not proceed as if a command had succeeded (issue #151). This matches the
  // exit CODE of the unknown-command case (both 2); the output STREAM
  // deliberately differs — a bare invocation has no error line, so its usage
  // goes to stderr, whereas unknown-command writes its "Unknown command"
  // error to stderr and the usage that follows to stdout.
  if (filteredArgv.length === 0) {
    printHelp(process.stderr)
    return 2
  }

  // A first token that looks like a flag (starts with '-') but isn't a
  // recognized top-level flag is a typo, not "no command given" — it must
  // exit 2, never silently print help with exit 0 (regression: issue #69,
  // `vaultkeeper --bogus` previously exited 0).
  if (firstArg?.startsWith('-') === true) {
    process.stderr.write(`Error: unknown option '${firstArg}'\n`)
    // Print the Usage: block so an unknown top-level flag matches the
    // unknown-command case (and subcommand-level usage errors), all of which
    // pair the error line on stderr with usage on stdout. Exit 2 (usage error).
    printHelp()
    return 2
  }

  // Defensive fallback: parseArgs with allowPositionals should always set
  // subcommand to firstArg when firstArg doesn't start with '-', but if it
  // somehow didn't, treat it the same as a bare invocation — a usage error
  // (issue #151), not a successful help print.
  if (subcommand === undefined) {
    printHelp(process.stderr)
    return 2
  }

  const configDir = resolveConfigDir(configDirFlag)

  switch (subcommand) {
    case 'exec': {
      const { execCommand } = await import('./commands/exec.js')
      return execCommand(commandArgs, configDir)
    }
    case 'doctor': {
      const { doctorCommand } = await import('./commands/doctor.js')
      return doctorCommand(commandArgs, configDir)
    }
    case 'approve': {
      const { approveCommand } = await import('./commands/approve.js')
      return approveCommand(commandArgs, configDir)
    }
    case 'dev-mode': {
      const { devModeCommand } = await import('./commands/dev-mode.js')
      return devModeCommand(commandArgs, configDir)
    }
    case 'store': {
      const { storeCommand } = await import('./commands/store.js')
      return storeCommand(commandArgs, configDir)
    }
    case 'delete': {
      const { deleteCommand } = await import('./commands/delete.js')
      return deleteCommand(commandArgs, configDir)
    }
    case 'config': {
      const { configCommand } = await import('./commands/config.js')
      return configCommand(commandArgs, configDir)
    }
    case 'rotate-key': {
      const { rotateKeyCommand } = await import('./commands/rotate-key.js')
      return rotateKeyCommand(commandArgs, configDir)
    }
    case 'revoke-key': {
      const { revokeKeyCommand } = await import('./commands/revoke-key.js')
      return revokeKeyCommand(commandArgs, configDir)
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
