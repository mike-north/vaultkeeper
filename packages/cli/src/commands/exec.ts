/**
 * The `vaultkeeper exec` command — inject a secret as an env var and run a command.
 *
 * Flow:
 * 1. Parse flags and the command after `--`
 * 2. If `--cache`, check for a cached JWE token
 * 3. If no cached token: prompt for approval, THEN retrieve and setup the secret
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
import { VaultKeeper } from 'vaultkeeper'
import { promptApproval } from '../approval.js'
import { readCachedToken, writeCachedToken, invalidateCache } from '../cache.js'
import { RedactingStream } from '../redact.js'
import { formatError } from '../output.js'

export async function execCommand(args: string[]): Promise<number> {
  // Find the -- separator to split CLI flags from the wrapped command
  const dashDashIdx = args.indexOf('--')
  if (dashDashIdx === -1) {
    process.stderr.write('Error: Must provide command after --\n')
    process.stderr.write(
      'Usage: vaultkeeper exec --secret <name> --env <VAR> --caller <path> -- <command...>\n',
    )
    return 1
  }

  const flagArgs = args.slice(0, dashDashIdx)
  const command = args.slice(dashDashIdx + 1)

  if (command.length === 0) {
    process.stderr.write('Error: No command provided after --\n')
    return 1
  }

  const { values } = parseArgs({
    args: flagArgs,
    options: {
      secret: { type: 'string' },
      env: { type: 'string' },
      caller: { type: 'string' },
      reason: { type: 'string' },
      cache: { type: 'boolean', default: false },
      'no-redact': { type: 'boolean', default: false },
    },
    strict: true,
  })

  const secret = values.secret
  const envVar = values.env
  const caller = values.caller

  if (secret === undefined || envVar === undefined || caller === undefined) {
    process.stderr.write('Error: --secret, --env, and --caller are required\n')
    return 1
  }

  const callerPath = path.resolve(caller)
  // parseArgs with default: false types these as boolean (never undefined)
  const useCache: boolean = values.cache
  const noRedact: boolean = values['no-redact']

  try {
    const vault = await VaultKeeper.init()

    // Check cache first if --cache
    let jwe: string | undefined
    if (useCache) {
      jwe = await readCachedToken(callerPath, secret)
    }

    if (jwe === undefined) {
      // [C1 fix] Prompt for approval BEFORE retrieving the secret.
      // vault.setup() retrieves the secret from the backend and embeds it
      // in a JWE, so we must get user consent first.
      const approved = await promptApproval({
        caller: callerPath,
        trustInfo: 'Pending verification',
        secret,
        reason: values.reason,
      })

      if (!approved) {
        process.stderr.write('Access denied by user.\n')
        return 1
      }

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
      // If cached token failed, invalidate and retry without cache
      if (useCache) {
        await invalidateCache(callerPath, secret)
        process.stderr.write('Cached token expired, re-authenticating...\n')
        // [C2 fix] Retry by toggling the useCache flag off internally
        // rather than filtering args (which could corrupt the wrapped command).
        jwe = undefined
        const approved = await promptApproval({
          caller: callerPath,
          trustInfo: 'Pending verification',
          secret,
          reason: values.reason,
        })
        if (!approved) {
          process.stderr.write('Access denied by user.\n')
          return 1
        }
        jwe = await vault.setup(secret, { executablePath: callerPath })
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
