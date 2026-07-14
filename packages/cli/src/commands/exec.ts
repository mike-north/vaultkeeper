/**
 * The `vaultkeeper exec` command — inject a secret as an env var and run a command.
 *
 * Flow:
 * 1. Parse flags and the command after `--`
 * 2. Enforce the TOFU trust gate for the caller (runs on every invocation,
 *    including `--cache` hits, so a cached token never bypasses trust). A
 *    trusted caller passes without a prompt; an untrusted caller is prompted
 *    interactively, unless `--yes`/`VAULTKEEPER_YES` approves it non-interactively
 *    or, on non-TTY stdin, the command fails with remediation guidance
 * 3. If `--cache`, check for a cached JWE token; otherwise retrieve and setup
 *    the secret into a fresh JWE
 * 4. Authorize the JWE → obtain a CapabilityToken
 * 5. Read the secret value via the accessor
 * 6. Spawn the child process with the secret injected as an env var
 * 7. Pipe stdout/stderr through RedactingStream (unless `--no-redact`)
 * 8. Exit with the child's exit code
 *
 * Note on secret lifetime: The secret must be converted to a JS string for env
 * var injection via `child_process.spawn`. This pins it in the V8 heap beyond
 * the `SecretAccessor` callback scope. This is an accepted tradeoff — the CLI
 * spawn boundary requires a string, and RedactingStream prevents leakage in
 * output. The string is not persisted or returned.
 *
 * @internal
 */

import { parseArgs } from 'node:util'
import { spawn } from 'node:child_process'
import * as path from 'node:path'
import { VaultKeeper, IdentityMismatchError } from 'vaultkeeper'
import { promptApproval } from '../approval.js'
import { readCachedToken, writeCachedToken, invalidateCache } from '../cache.js'
import { RedactingStream } from '../redact.js'
import { shouldSkipDoctor } from '../skip-doctor.js'
import { shouldAutoApprove } from '../auto-approve.js'
import { formatError } from '../output.js'

/**
 * Enforce the TOFU trust gate for `callerPath` before any secret is retrieved
 * or any cached token is used.
 *
 * Behavior depends on the caller's current trust status:
 *
 * - **Trusted** (current hash approved in the manifest): returns `true` without
 *   an interactive prompt, so trusted callers work on non-TTY stdin.
 * - **Hash mismatch** (caller is known to the manifest but its hash changed
 *   since approval): throws {@link IdentityMismatchError} with re-approval
 *   guidance. It does not prompt — `VaultKeeper.setup()` rejects the same hash
 *   conflict regardless of the user's answer, so prompting would waste it.
 *   `autoApprove` never overrides this: a changed binary must be re-approved
 *   with `vaultkeeper approve`, not silently trusted.
 * - **Never approved**, with `autoApprove` set (`--yes`/`VAULTKEEPER_YES`):
 *   returns `true` without prompting. The subsequent `setup()` records the
 *   caller's hash via TOFU, exactly as an interactive `y` would.
 * - **Never approved**, non-TTY stdin, no `autoApprove`: throws with
 *   remediation guidance (pre-approve via `vaultkeeper approve`, or re-run with
 *   `--yes`) — there is no way to prompt.
 * - **Never approved**, interactive TTY: shows an approval prompt and returns
 *   its result (`false` if the user declines).
 *
 * @returns `true` if access is authorized, `false` if the user declined.
 * @throws {IdentityMismatchError} When the caller's hash changed from a
 *   previously approved value.
 * @throws When approval is required but cannot be obtained (non-TTY stdin
 *   without `--yes`), or when the caller path cannot be read for hashing.
 */
async function enforceTrustGate(
  vault: VaultKeeper,
  callerPath: string,
  secret: string,
  reason: string | undefined,
  autoApprove: boolean,
): Promise<boolean> {
  const trust = await vault.checkExecutableTrust(callerPath)
  if (trust.trusted) {
    process.stderr.write('Trust: verified (hash matches trust manifest)\n')
    return true
  }

  if (trust.hashMismatch) {
    // On a mismatch the manifest holds at least one prior approved hash; report
    // the most recently approved one as previousHash and the on-disk hash as
    // currentHash so the error payload is accurate for diagnosis.
    const previousHash = trust.approvedHashes.at(-1) ?? trust.hash
    throw new IdentityMismatchError(
      `Executable at ${callerPath} has changed since it was approved. ` +
        `If this change is expected, re-approve it with: vaultkeeper approve --script ${callerPath}`,
      previousHash,
      trust.hash,
    )
  }

  // Never-approved caller. --yes / VAULTKEEPER_YES approves this invocation
  // without prompting; setup() then records the hash via TOFU just as an
  // interactive "y" would.
  if (autoApprove) {
    process.stderr.write('Trust: approved via --yes (recording caller in trust manifest)\n')
    return true
  }

  // No non-interactive approval and no TTY to prompt on: fail with actionable
  // guidance instead of the raw "requires interactive approval" error.
  // isTTY is `true` only on a real terminal; `undefined`/`false` means non-TTY.
  if (!process.stdin.isTTY) {
    throw new Error(
      `Secret access for ${callerPath} requires approval, but stdin is not a TTY, ` +
        `so no interactive prompt can be shown.\n` +
        `To approve non-interactively, either:\n` +
        `  - pre-approve the caller once:  vaultkeeper approve --script ${callerPath}\n` +
        `  - or approve just this run:      re-run with --yes (or set VAULTKEEPER_YES=1)`,
    )
  }

  return promptApproval({
    caller: callerPath,
    trustInfo: 'Pending verification',
    secret,
    reason,
  })
}

function printExecHelp(): void {
  process.stdout.write(
    'Usage: vaultkeeper exec --secret <name> --env <VAR> --caller <path> [options] -- <command...>\n\n' +
      'Options:\n' +
      '  --secret <name>    Name of the secret to inject\n' +
      '  --env <VAR>        Environment variable name to inject the secret into\n' +
      '  --caller <path>    Path to the calling executable (used for TOFU verification)\n' +
      '  --reason <text>    Human-readable reason for access (optional)\n' +
      '  --yes              Approve an untrusted caller for this invocation without\n' +
      '                     an interactive prompt, recording it in the trust manifest\n' +
      '                     (for CI/non-interactive use; never the default)\n' +
      '  --cache            Cache the JWE token for subsequent invocations\n' +
      '  --no-redact        Do not redact the secret from output\n' +
      '  --skip-doctor      Skip doctor preflight checks\n' +
      '  -h, --help         Show this help message\n\n' +
      'Approval and TTY requirement:\n' +
      '  A caller that is not yet trusted requires approval. On an interactive\n' +
      '  terminal you are prompted [y/N]. With non-TTY stdin (CI, pipes) there is\n' +
      '  no prompt, so you must either pre-approve the caller with\n' +
      '  `vaultkeeper approve --script <caller>` or pass --yes (or VAULTKEEPER_YES=1)\n' +
      '  to approve this invocation. Once trusted, exec never prompts again.\n\n' +
      'Environment variables:\n' +
      '  VAULTKEEPER_YES=1           Approve an untrusted caller non-interactively\n' +
      '                              (same as --yes)\n' +
      '  VAULTKEEPER_SKIP_DOCTOR=1   Skip doctor preflight checks\n',
  )
}

export async function execCommand(args: string[]): Promise<number> {
  // Handle --help / -h before any other processing.
  if (args.includes('--help') || args.includes('-h')) {
    printExecHelp()
    return 0
  }

  // Find the -- separator to split CLI flags from the wrapped command
  const dashDashIdx = args.indexOf('--')
  if (dashDashIdx === -1) {
    process.stderr.write('Error: Must provide command after --\n')
    process.stderr.write(
      'Usage: vaultkeeper exec --secret <name> --env <VAR> --caller <path> -- <command...>\n',
    )
    // Exit code 2: usage error (missing required separator)
    return 2
  }

  const flagArgs = args.slice(0, dashDashIdx)
  const command = args.slice(dashDashIdx + 1)

  if (command.length === 0) {
    process.stderr.write('Error: No command provided after --\n')
    // Exit code 2: usage error (empty command after separator)
    return 2
  }

  const { values } = parseArgs({
    args: flagArgs,
    options: {
      secret: { type: 'string' },
      env: { type: 'string' },
      caller: { type: 'string' },
      reason: { type: 'string' },
      yes: { type: 'boolean', default: false },
      cache: { type: 'boolean', default: false },
      'no-redact': { type: 'boolean', default: false },
      'skip-doctor': { type: 'boolean', default: false },
    },
    strict: true,
  })

  const secret = values.secret
  const envVar = values.env
  const caller = values.caller

  if (secret === undefined || envVar === undefined || caller === undefined) {
    process.stderr.write('Error: --secret, --env, and --caller are required\n')
    // Exit code 2: usage error (missing required flags)
    return 2
  }

  const callerPath = path.resolve(caller)
  // parseArgs with default: false types these as boolean (never undefined)
  const useCache: boolean = values.cache
  const noRedact: boolean = values['no-redact']
  const skipDoctor = shouldSkipDoctor(values['skip-doctor'])
  const autoApprove = shouldAutoApprove(values.yes)

  try {
    const vault = await VaultKeeper.init({ skipDoctor })

    // Enforce the trust gate BEFORE touching the cache or retrieving the
    // secret. This runs on every invocation — including a `--cache` hit — so a
    // previously cached JWE can never let a modified or never-approved caller
    // inherit trust it no longer (or never) held. A modified caller surfaces an
    // identity-mismatch error here rather than silently reusing a cached token.
    const approved = await enforceTrustGate(vault, callerPath, secret, values.reason, autoApprove)
    if (!approved) {
      process.stderr.write('Access denied by user.\n')
      return 1
    }

    // Check cache only after the caller has cleared the trust gate.
    let jwe: string | undefined
    if (useCache) {
      jwe = await readCachedToken(callerPath, secret)
    }

    if (jwe === undefined) {
      jwe = await vault.setup(secret, { executablePath: callerPath })

      // Cache if requested
      if (useCache) {
        await writeCachedToken(callerPath, secret, jwe)
      }
    }

    // Authorize and get secret
    let secretValue: string | undefined
    try {
      const { token } = await vault.authorize(jwe)
      const accessor = vault.getSecret(token)
      accessor.read((buf) => {
        secretValue = buf.toString('utf8')
      })
    } catch (err) {
      // If the cached token failed (e.g. expired), invalidate and mint a fresh
      // one. Trust was already enforced above, so no re-prompt is needed.
      if (useCache) {
        await invalidateCache(callerPath, secret)
        process.stderr.write('Cached token expired, re-authenticating...\n')
        jwe = await vault.setup(secret, { executablePath: callerPath })
        // Write the new token back to cache so subsequent invocations benefit
        await writeCachedToken(callerPath, secret, jwe)
        const retryResult = await vault.authorize(jwe)
        const retryAccessor = vault.getSecret(retryResult.token)
        retryAccessor.read((buf) => {
          secretValue = buf.toString('utf8')
        })
      } else {
        throw err
      }
    }

    if (secretValue === undefined) {
      process.stderr.write('Error: Failed to read secret value\n')
      return 1
    }

    // Spawn child process
    const commandName = command[0]
    if (commandName === undefined) {
      process.stderr.write('Error: Empty command\n')
      return 1
    }

    const child = spawn(commandName, command.slice(1), {
      env: { ...process.env, [envVar]: secretValue },
      stdio: ['inherit', 'pipe', 'pipe'],
    })

    // Pipe output through redaction (or directly)
    if (noRedact) {
      child.stdout.pipe(process.stdout)
      child.stderr.pipe(process.stderr)
    } else {
      const stdoutRedactor = new RedactingStream(secretValue)
      const stderrRedactor = new RedactingStream(secretValue)
      child.stdout.pipe(stdoutRedactor).pipe(process.stdout)
      child.stderr.pipe(stderrRedactor).pipe(process.stderr)
    }

    // [W7 fix] Wait for child to exit, handling both 'close' and 'error' events
    return await new Promise<number>((resolve, reject) => {
      child.on('error', (err) => {
        reject(err)
      })
      child.on('close', (code) => {
        resolve(code ?? 1)
      })
    })
  } catch (err) {
    process.stderr.write(`${formatError(err)}\n`)
    return 1
  }
}
