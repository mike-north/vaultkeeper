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
 *       argument, and empty stdin for `store`/`sign`/`verify`. A bare
 *       invocation with no arguments is NOT a usage error — it renders the
 *       same full help as `--help` and exits 0 (issue #202); only a token
 *       that looks like a command/flag but isn't recognized exits 2.
 *   3 — `verify` only: signature did not verify (deliberate, documented
 *       exception to the 0/1/2 taxonomy so scripts can tell a bad signature
 *       from a broken tool — see commands/verify.ts)
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
      '  key          Manage signing keys (create, export)\n' +
      '  sign         Sign stdin with a signing key (detached JWS to stdout)\n' +
      '  verify       Verify a detached signature offline (exit 3 = invalid)\n' +
      '  config       Manage configuration\n' +
      '  rotate-key   Rotate the encryption key\n' +
      '  revoke-key   Emergency key revocation\n\n' +
      'Global options:\n' +
      '  --version, -V, -v    Print the version number and exit\n' +
      CONFIG_DIR_HELP_OPTION +
      '  -h, --help           Show this help message\n' +
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

  // Handle --version / -V / -v before subcommand dispatch.
  // parseArgs treats these as option values (not positionals) with strict:false,
  // so we inspect the first filtered token directly to detect them. Both the
  // conventional `-V` and the commonly-guessed `-v` are accepted (issue #202):
  // the CLI has no verbose flag, so there's no `-v` collision to worry about.
  if (firstArg === '--version' || firstArg === '-V' || firstArg === '-v') {
    process.stdout.write(`${packageVersion}\n`)
    return 0
  }

  // An explicit --help / -h is a successful request for usage: print to
  // stdout and exit 0.
  if (firstArg === '--help' || firstArg === '-h') {
    printHelp()
    return 0
  }

  // A bare invocation (no arguments at all) renders the full help and exits 0
  // (issue #202). It prints the identical text `--help` does, so it is a help
  // request, not a usage error — exiting 2 here (as #151 originally did) made a
  // plain `vaultkeeper` read as a failure to scripts checking the exit code,
  // even though nothing was misused. A genuine misuse still exits 2: an
  // unrecognized flag (below), an unknown command, or a missing/invalid
  // argument — none of which reach this branch, which fires only for truly
  // empty argv.
  if (filteredArgv.length === 0) {
    printHelp()
    return 0
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
  // subcommand to firstArg when firstArg doesn't start with '-', and the
  // truly-empty argv case is already handled above. If we somehow reach here
  // with no subcommand despite a non-empty argv, treat it conservatively as a
  // usage error (exit 2) rather than silently succeeding.
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
    case 'key': {
      const { keyCommand } = await import('./commands/key.js')
      return keyCommand(commandArgs, configDir)
    }
    case 'sign': {
      const { signCommand } = await import('./commands/sign.js')
      return signCommand(commandArgs, configDir)
    }
    case 'verify': {
      // verify is fully offline: no config dir, backend, or vault init.
      const { verifyCommand } = await import('./commands/verify.js')
      return verifyCommand(commandArgs)
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
