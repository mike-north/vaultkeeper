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
 * 3. For an already-trusted caller with `--cache`, reuse a cached JWE token;
 *    otherwise (including a just-approved caller) retrieve and setup the secret
 *    into a fresh JWE, which also records a just-approved caller's trust
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
import {
  VaultKeeper,
  IdentityMismatchError,
  SecretNotFoundError,
  defaultBackendType,
} from 'vaultkeeper'
import { promptApproval } from '../approval.js'
import { readCachedToken, writeCachedToken, invalidateCache } from '../cache.js'
import { RedactingStream } from '../redact.js'
import { shouldSkipDoctor } from '../skip-doctor.js'
import { shouldAutoApprove } from '../auto-approve.js'
import { shellQuote } from '../shell-quote.js'
import { formatError } from '../output.js'
import { CONFIG_DIR_HELP_OPTION, CONFIG_DIR_HELP_ENV } from '../config-dir.js'
import { configFileExists, noConfigMessage } from '../config-status.js'

/**
 * Outcome of the TOFU trust gate.
 *
 * - `trusted`: the caller's current hash is already approved in the manifest.
 * - `approved`: the caller was just approved for this invocation (interactive
 *   `y` or `--yes`/`VAULTKEEPER_YES`) and its hash is not yet recorded.
 * - `denied`: the user declined the interactive prompt.
 */
type TrustGateOutcome = 'trusted' | 'approved' | 'denied'

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
 * @returns the {@link TrustGateOutcome}: `trusted` (already approved), `approved`
 *   (just approved this run — the caller still needs recording via `setup()`),
 *   or `denied` (user declined).
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
): Promise<TrustGateOutcome> {
  const trust = await vault.checkExecutableTrust(callerPath)
  if (trust.trusted) {
    process.stderr.write('Trust: verified (hash matches trust manifest)\n')
    return 'trusted'
  }

  if (trust.hashMismatch) {
    // On a mismatch the manifest holds at least one prior approved hash; report
    // the most recently approved one as previousHash and the on-disk hash as
    // currentHash so the error payload is accurate for diagnosis. The remediation
    // command shell-quotes the path so it is safe to copy and paste verbatim.
    const previousHash = trust.approvedHashes.at(-1) ?? trust.hash
    throw new IdentityMismatchError(
      `Executable at ${callerPath} has changed since it was approved. ` +
        `If this change is expected, re-approve it with: vaultkeeper approve --script ${shellQuote(callerPath)}`,
      previousHash,
      trust.hash,
    )
  }

  // Never-approved caller. --yes / VAULTKEEPER_YES approves this invocation
  // without prompting; the caller reports "approved" so the command records the
  // hash via setup() (TOFU first-encounter) just as an interactive "y" would.
  if (autoApprove) {
    process.stderr.write('Trust: approved via --yes (recording caller in trust manifest)\n')
    return 'approved'
  }

  // No non-interactive approval and no TTY to prompt on: fail with actionable
  // guidance instead of the raw "requires interactive approval" error. The
  // caller path is shell-quoted so the suggested command is copy-paste safe.
  // isTTY is `true` only on a real terminal; `undefined`/`false` means non-TTY.
  if (!process.stdin.isTTY) {
    throw new Error(
      `Secret access for ${callerPath} requires approval, but stdin is not a TTY, ` +
        `so no interactive prompt can be shown.\n` +
        `To approve non-interactively, either:\n` +
        `  - pre-approve the caller once:  vaultkeeper approve --script ${shellQuote(callerPath)}\n` +
        `  - or approve just this run:      re-run with --yes (or set VAULTKEEPER_YES=1)`,
    )
  }

  return (await promptApproval({
    caller: callerPath,
    trustInfo: 'Pending verification',
    secret,
    reason,
  }))
    ? 'approved'
    : 'denied'
}

/**
 * Render a concise, accurate description of why authorizing a cached token
 * failed, for the re-authentication notice. Preserves the error's class name
 * (e.g. `KeyRevokedError`, `TokenExpiredError`) so distinct failures are no
 * longer collapsed into a single misleading "expired" message.
 */
function describeAuthzFailure(err: unknown): string {
  if (err instanceof Error) {
    return err.name !== '' ? `${err.name}: ${err.message}` : err.message
  }
  return String(err)
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
      '  --cache            Cache the JWE token so a later invocation by the same\n' +
      '                     trusted caller reuses it without re-minting. The token\n' +
      "                     is reusable until it expires (the secret's TTL); after\n" +
      '                     that, or after a key rotation/revocation, exec mints a\n' +
      '                     fresh one automatically\n' +
      '  --no-redact        Do not redact the secret from output\n' +
      '  --skip-doctor      Skip doctor preflight checks\n' +
      CONFIG_DIR_HELP_OPTION +
      '  -h, --help         Show this help message\n\n' +
      'Approval and TTY requirement:\n' +
      '  A caller that is not yet trusted requires approval. On an interactive\n' +
      '  terminal you are prompted [y/N]. With non-TTY stdin (CI, pipes) there is\n' +
      '  no prompt, so you must either pre-approve the caller with\n' +
      '  "vaultkeeper approve --script <caller>" or pass --yes (or VAULTKEEPER_YES=1)\n' +
      '  to approve this invocation. Once trusted, exec never prompts again.\n\n' +
      'Example (--caller identifies the invoking script or binary, not the\n' +
      'wrapped command after --):\n' +
      '  vaultkeeper exec --secret db-password --env DB_PASSWORD \\\n' +
      '    --caller ./deploy.sh -- psql -U admin\n' +
      '  # deploy.sh is the trusted caller; psql is the command that receives\n' +
      '  # DB_PASSWORD in its environment.\n\n' +
      'Environment variables:\n' +
      '  VAULTKEEPER_YES=1           Approve an untrusted caller non-interactively\n' +
      '                              (same as --yes)\n' +
      '  VAULTKEEPER_SKIP_DOCTOR=1   Skip doctor preflight checks\n' +
      CONFIG_DIR_HELP_ENV,
  )
}

export async function execCommand(args: string[], configDir: string): Promise<number> {
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

  let values: {
    secret?: string
    env?: string
    caller?: string
    reason?: string
    yes: boolean
    cache: boolean
    'no-redact': boolean
    'skip-doctor': boolean
  }
  try {
    ;({ values } = parseArgs({
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
    }))
  } catch (err) {
    // Regression: issue #69 — an unrecognized flag previously propagated
    // uncaught and exited 1 via bin.ts's fatal-error handler instead of the
    // usage-error exit code 2.
    if (err instanceof Error) {
      process.stderr.write(`Error: ${err.message}\n`)
    }
    process.stderr.write(
      'Usage: vaultkeeper exec --secret <name> --env <VAR> --caller <path> [options] -- <command...>\n',
    )
    return 2
  }

  const secret = values.secret
  const envVar = values.env
  const caller = values.caller

  if (secret === undefined || envVar === undefined || caller === undefined) {
    process.stderr.write('Error: --secret, --env, and --caller are required\n')
    // Exit code 2: usage error (missing required flags)
    return 2
  }

  // Reject empty/whitespace-only values with the same exit code and error
  // style as a missing flag (consistent with store/delete's --name check).
  // Before this fix each had its own gap:
  //   --secret ""  -> vault.secretExists() threw VaultError, exit 1
  //   --caller ""  -> path.resolve('') resolves to cwd, a directory; hashing
  //                   it threw FilesystemError (EISDIR), exit 1
  //   --env ""     -> silently succeeded (exit 0): '' is a syntactically
  //                   valid env var key, so the secret was injected into an
  //                   unusable key and the wrapped command ran normally —
  //                   the worst of the three, since it failed silently.
  if (secret.trim() === '' || envVar.trim() === '' || caller.trim() === '') {
    process.stderr.write(
      'Error: --secret, --env, and --caller must not be empty or whitespace-only\n',
    )
    process.stderr.write(
      'Usage: vaultkeeper exec --secret <name> --env <VAR> --caller <path> [options] -- <command...>\n',
    )
    // Exit code 2: usage error (invalid flag value)
    return 2
  }

  const callerPath = path.resolve(caller)
  // parseArgs with default: false types these as boolean (never undefined)
  const useCache: boolean = values.cache
  const noRedact: boolean = values['no-redact']
  const skipDoctor = shouldSkipDoctor(values['skip-doctor'])
  const autoApprove = shouldAutoApprove(values.yes)

  try {
    // No-config story is uniform across store/delete/exec/config show/doctor
    // (issue #68): fall back to platform defaults and say so, rather than
    // silently defaulting.
    if (!(await configFileExists(configDir))) {
      process.stderr.write(noConfigMessage(defaultBackendType()))
    }

    const vault = await VaultKeeper.init({ configDir, skipDoctor })

    // Validate input preconditions (secret existence) BEFORE the trust gate.
    // The trust gate's non-TTY path fails fast with an approval-required
    // error, which previously masked a simple "secret not found" — a
    // nonexistent secret now reports SecretNotFoundError-style messaging
    // regardless of TTY (issue #69). This check is side-effect-free (unlike
    // `setup()`, it never touches the TOFU trust manifest), so it cannot be
    // used to bypass caller approval.
    if (!(await vault.secretExists(secret))) {
      throw new SecretNotFoundError(
        `Secret "${secret}" not found in ${vault.activeBackendType} backend`,
      )
    }

    // Enforce the trust gate BEFORE touching the cache or retrieving the
    // secret. This runs on every invocation — including a `--cache` hit — so a
    // previously cached JWE can never let a modified or never-approved caller
    // inherit trust it no longer (or never) held. A modified caller surfaces an
    // identity-mismatch error here rather than silently reusing a cached token.
    const outcome = await enforceTrustGate(vault, callerPath, secret, values.reason, autoApprove)
    if (outcome === 'denied') {
      process.stderr.write('Access denied by user.\n')
      return 1
    }

    // Only a caller that was ALREADY trusted may reuse a cached token. A caller
    // that was just approved this run (--yes or interactive "y") must go through
    // setup(), which records its hash in the trust manifest (TOFU first
    // encounter) — a cached token (the cache dir is independent of the trust
    // manifest) must never short-circuit that recording, or the approval would
    // not persist for later runs.
    let jwe: string | undefined
    let jweFromCache = false
    if (useCache && outcome === 'trusted') {
      jwe = await readCachedToken(callerPath, secret)
      jweFromCache = jwe !== undefined
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
      // Only a token that came from the cache is transparently recoverable: the
      // caller was already trusted (the trust gate ran above), so we can mint a
      // fresh token without re-prompting. A freshly-minted token that fails to
      // authorize is a genuine error and must surface unchanged.
      //
      // Crucially, we report the ACTUAL failure (e.g. KeyRevokedError,
      // TokenExpiredError) rather than mislabeling every failure as "expired" —
      // the previous behavior hid key-revocation and other faults behind a
      // generic "Cached token expired" message.
      if (!jweFromCache) {
        throw err
      }
      await invalidateCache(callerPath, secret)
      process.stderr.write(
        `Cached token could not be authorized (${describeAuthzFailure(err)}); re-authenticating...\n`,
      )
      jwe = await vault.setup(secret, { executablePath: callerPath })
      // Write the new token back to cache so subsequent invocations benefit
      await writeCachedToken(callerPath, secret, jwe)
      const retryResult = await vault.authorize(jwe)
      const retryAccessor = vault.getSecret(retryResult.token)
      retryAccessor.read((buf) => {
        secretValue = buf.toString('utf8')
      })
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
    process.stderr.write(`${formatError(err, configDir)}\n`)
    return 1
  }
}
