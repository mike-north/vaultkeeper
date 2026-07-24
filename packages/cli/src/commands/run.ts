/**
 * The `vaultkeeper run` command — launch a command with one or more secrets
 * available in its subshell, with full stdio and signal transparency
 * (issue #333, surface-governance ruling B9: `run` is the single launcher
 * verb; `exec` folds into it).
 *
 * Today this TS CLI only supports `run`'s `--token <jwe> [--as VAR]` source
 * (redeem an already-minted JWE and inject its secret) — the `exec --secret
 * --env --caller` flow that mints from scratch/enforces the TOFU trust gate
 * stays on `exec` unchanged (a distinct operation the fold doesn't touch).
 * `--profile`/`--profile-file` (environment *composition*) are native
 * Rust-CLI-only for now, matching the precedent PR #335 set: this TS CLI has
 * no profile-resolution concept yet, and porting it is out of scope here.
 *
 * Transparency contract (matching the native Rust `run`'s, issue #279):
 * - stdio is inherited (`stdio: 'inherit'`), never piped/captured — the
 *   child gets the real fds directly, so passthrough is byte-exact by
 *   construction. This CLI never redacts on this path (there is no piped
 *   stream to redact through).
 * - SIGINT/SIGTERM sent to this process are forwarded to the child, which
 *   then keeps waiting rather than exiting first and orphaning the child.
 * - The child's exit code is propagated; a signal-killed child yields
 *   `128+N`.
 *
 * @internal
 */

import { parseArgs } from 'node:util'
import { spawn } from 'node:child_process'
import * as os from 'node:os'
import { VaultKeeper, ExecError, defaultBackendType } from 'vaultkeeper'
import { shouldSkipDoctor } from '../skip-doctor.js'
import { formatError } from '../output.js'
import { CONFIG_DIR_HELP_OPTION, CONFIG_DIR_HELP_ENV } from '../config-dir.js'
import { configFileExists, noConfigMessage } from '../config-status.js'

/** The default env var a redeemed token's secret is injected under — the
 * same default `exec` has always used, so `run --token <jwe>` (no `--as`)
 * matches `exec --token <jwe>` (issue #333 AC1). */
export const DEFAULT_TOKEN_VAR = 'VAULTKEEPER_SECRET'

/** `[A-Z_][A-Z0-9_]*` — the same env-var-name shape the native Rust CLI's
 * `--as`/`--set` validation is held to (`vaultkeeper_core::run`). */
const VALID_ENV_VAR_NAME = /^[A-Z_][A-Z0-9_]*$/

function printRunHelp(): void {
  process.stdout.write(
    'Usage: vaultkeeper run --token <jwe> [--as VAR] [options] -- <command...>\n\n' +
      'Options:\n' +
      '  --token <jwe>      Redeem an already-minted JWE token and inject its\n' +
      "                     secret as an env var (the deprecated exec's behavior,\n" +
      '                     folded into run). Required.\n' +
      '  --as <VAR>         Env var the redeemed secret is injected under.\n' +
      `                     Defaults to ${DEFAULT_TOKEN_VAR}.\n` +
      '  --skip-doctor      Skip doctor preflight checks\n' +
      CONFIG_DIR_HELP_OPTION +
      '  -h, --help         Show this help message\n\n' +
      'Note: --profile/--profile-file (environment composition from a named\n' +
      'profile) are supported by the native Rust CLI only today — this TS CLI\n' +
      'has no profile-resolution concept yet.\n\n' +
      'Environment variables:\n' +
      '  VAULTKEEPER_SKIP_DOCTOR=1   Skip doctor preflight checks\n' +
      CONFIG_DIR_HELP_ENV,
  )
}

/** Map a Node child-process signal name (e.g. `'SIGTERM'`) to its POSIX
 * signal number, for the `128+N` exit-code convention. Falls back to `1`
 * for a signal Node reports that has no listed number on this platform
 * (should not happen in practice, but this must never throw). */
function signalNumber(signal: NodeJS.Signals): number {
  return os.constants.signals[signal]
}

export async function runCommand(args: string[], configDir: string): Promise<number> {
  if (args.includes('--help') || args.includes('-h')) {
    printRunHelp()
    return 0
  }

  const dashDashIdx = args.indexOf('--')
  if (dashDashIdx === -1) {
    process.stderr.write('Error: Must provide command after --\n')
    process.stderr.write('Usage: vaultkeeper run --token <jwe> [--as VAR] -- <command...>\n')
    return 2
  }

  const flagArgs = args.slice(0, dashDashIdx)
  const command = args.slice(dashDashIdx + 1)

  if (command.length === 0) {
    process.stderr.write('Error: No command provided after --\n')
    return 2
  }

  let values: { token?: string; as?: string; 'skip-doctor': boolean }
  try {
    ;({ values } = parseArgs({
      args: flagArgs,
      options: {
        token: { type: 'string' },
        as: { type: 'string' },
        'skip-doctor': { type: 'boolean', default: false },
      },
      strict: true,
    }))
  } catch (err) {
    if (err instanceof Error) {
      process.stderr.write(`Error: ${err.message}\n`)
    }
    process.stderr.write('Usage: vaultkeeper run --token <jwe> [--as VAR] -- <command...>\n')
    return 2
  }

  const token = values.token
  if (token === undefined || token.trim() === '') {
    process.stderr.write('Error: --token is required\n')
    process.stderr.write('Usage: vaultkeeper run --token <jwe> [--as VAR] -- <command...>\n')
    return 2
  }

  const asVar = values.as ?? DEFAULT_TOKEN_VAR
  if (!VALID_ENV_VAR_NAME.test(asVar)) {
    process.stderr.write(
      `Error: --as "${asVar}" is not a valid env var name — must match [A-Z_][A-Z0-9_]*\n`,
    )
    return 2
  }

  const skipDoctor = shouldSkipDoctor(values['skip-doctor'])

  try {
    if (!(await configFileExists(configDir))) {
      process.stderr.write(noConfigMessage(defaultBackendType()))
    }

    const vault = await VaultKeeper.init({ configDir, skipDoctor })

    const { token: capabilityToken } = await vault.authorize(token)
    const accessor = vault.getSecret(capabilityToken)
    let secretValue: string | undefined
    accessor.read((buf) => {
      secretValue = buf.toString('utf8')
    })
    if (secretValue === undefined) {
      process.stderr.write('Error: Failed to read secret value\n')
      return 1
    }

    return await launchWithFullTransparency(command, { [asVar]: secretValue })
  } catch (err) {
    process.stderr.write(`${formatError(err, configDir)}\n`)
    return 1
  }
}

/**
 * Launch `command` with `env` injected on top of the current environment,
 * full stdio inheritance, and SIGINT/SIGTERM forwarding — the same
 * transparency contract `crates/vaultkeeper-cli`'s native `run` provides
 * (issue #279, extended to this TS CLI's `run --token` by issue #333).
 */
async function launchWithFullTransparency(
  command: string[],
  env: Record<string, string>,
): Promise<number> {
  const commandName = command[0]
  if (commandName === undefined) {
    process.stderr.write('Error: Empty command\n')
    return 1
  }

  return new Promise<number>((resolve, reject) => {
    const child = spawn(commandName, command.slice(1), {
      env: { ...process.env, ...env },
      stdio: 'inherit',
    })

    // Installed before any await/tick beyond spawn() itself, mirroring the
    // native CLI's "handlers before spawn" ordering (issue #279) — a signal
    // arriving in the window right after launch must still be forwarded
    // rather than hitting this process's default disposition and orphaning
    // the child.
    const forward = (signal: NodeJS.Signals): void => {
      child.kill(signal)
    }
    process.on('SIGINT', forward)
    process.on('SIGTERM', forward)

    const cleanup = (): void => {
      process.removeListener('SIGINT', forward)
      process.removeListener('SIGTERM', forward)
    }

    child.on('error', (err: NodeJS.ErrnoException) => {
      cleanup()
      if (err.code === 'ENOENT') {
        reject(
          new ExecError(
            `Could not start "${commandName}" — no such file or directory. ` +
              `Check the command path and that it is executable.`,
            commandName,
          ),
        )
      } else if (err.code === 'EACCES') {
        reject(
          new ExecError(
            `Could not start "${commandName}" — permission denied. ` +
              `Check the command path and that it is executable.`,
            commandName,
          ),
        )
      } else {
        reject(err)
      }
    })

    child.on('exit', (code, signal) => {
      cleanup()
      if (signal !== null) {
        resolve(128 + signalNumber(signal))
        return
      }
      resolve(code ?? 1)
    })
  })
}
