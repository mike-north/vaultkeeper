import { parseArgs } from 'node:util'
import * as path from 'node:path'
import { VaultKeeper } from 'vaultkeeper'
import { formatError } from '../output.js'
import { CONFIG_DIR_HELP_OPTION, CONFIG_DIR_HELP_ENV } from '../config-dir.js'

function printApproveHelp(): void {
  process.stdout.write(
    'Usage: vaultkeeper approve --script <path>\n\n' +
      'Record a script hash in the TOFU trust manifest, marking the script as a\n' +
      'trusted caller for vaultkeeper exec.\n\n' +
      'When this is required:\n' +
      '  In a non-interactive or CI context (non-TTY stdin), approve is a REQUIRED\n' +
      "  first step before a new caller's first exec: there is no prompt to grant\n" +
      '  trust, so an un-approved caller fails. Pre-approve it here once (or pass\n' +
      '  exec --yes to approve a single run). On an interactive terminal exec can\n' +
      "  instead prompt [y/N] on first use, so approve is optional there — it's a\n" +
      '  way to grant trust ahead of time and avoid that prompt.\n\n' +
      'Running this on an already approved, unchanged script is idempotent.\n\n' +
      'Options:\n' +
      '  --script <path>   Path to the script to approve\n' +
      CONFIG_DIR_HELP_OPTION +
      '  -h, --help        Show this help message\n\n' +
      'Environment variables:\n' +
      CONFIG_DIR_HELP_ENV,
  )
}

export async function approveCommand(args: string[], configDir: string): Promise<number> {
  // Handle --help / -h before strict parseArgs.
  if (args.includes('--help') || args.includes('-h')) {
    printApproveHelp()
    return 0
  }

  let values: { script?: string }
  try {
    ;({ values } = parseArgs({
      args,
      options: {
        script: { type: 'string' },
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
    process.stderr.write('Usage: vaultkeeper approve --script <path>\n')
    return 2
  }

  if (values.script === undefined) {
    process.stderr.write('Error: --script is required\n')
    process.stderr.write('Usage: vaultkeeper approve --script <path>\n')
    // Exit code 2: usage error (missing required flag)
    return 2
  }

  const scriptPath = path.resolve(values.script)

  try {
    // Approving a hash is a trust-only operation: it touches the config dir and
    // trust manifest, never the secret backend. Skip the doctor preflight, and
    // VaultKeeper.init() itself resolves the backend lazily, so approve works
    // even when the configured backend or plugin is unavailable.
    const vault = await VaultKeeper.init({ configDir, skipDoctor: true })
    const status = await vault.approveExecutable(scriptPath)
    process.stdout.write(`Approved ${scriptPath} (hash: ${status.hash})\n`)
    return 0
  } catch (err) {
    process.stderr.write(`${formatError(err, configDir)}\n`)
    // Exit code 1: runtime error (e.g. missing script, unwritable manifest)
    return 1
  }
}
