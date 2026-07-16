/**
 * Per-access worker script for the 1Password SDK backend.
 *
 * @remarks
 * This script is spawned as a child process by `OnePasswordBackend` when
 * `accessMode` is set to `'per-access'`. It creates a fresh SDK client (which
 * triggers a biometric prompt via the desktop app), performs a single keyed
 * operation, writes the result to stdout as JSON, then exits immediately.
 *
 * argv layout:
 *   node one-password-worker.js <accountName> <vaultId> <secretId> [op]
 *
 * `op` is one of `'retrieve'` (default, for backward compatibility with the
 * original 3-argument invocation), `'store'`, or `'delete'`.
 *
 * For `'store'`, the secret value is read from **stdin** (UTF-8, until EOF) —
 * never argv — so it never appears in `ps`/process listings, shell history,
 * or logs (repo security rule; mirrors the stdin plumbing already used by
 * `execCommandFull` in `util/exec.ts`).
 *
 * stdout on success:
 *   `retrieve` — `{ "value": "<secret>" }`
 *   `store`/`delete` — `{ "ok": true }`
 * stdout on failure: `{ "error": "<message>", "code": "<code>" }`
 *
 * `store`/`delete` are the presence-covered write paths added by issue #211:
 * each spawns a fresh SDK client exactly like `retrieve` does, forcing the
 * same fresh biometric approval, so `OnePasswordBackend.getCapabilities()`
 * can report `store`/`delete` in `presenceEnforcedOperations` instead of
 * refusing them with `NotCapableError`.
 *
 * @see https://github.com/mike-north/vaultkeeper/issues/211
 */

import {
  INTEGRATION_NAME,
  SDK_NOT_INSTALLED_MESSAGE,
  PRESENCE_WRITE_TIMEOUT_MS,
  getIntegrationVersion,
  isModuleNotFoundError,
} from './one-password-constants.js'
import {
  storeSecretItem,
  deleteSecretItem,
  TAG,
  PASSWORD_FIELD_TITLE,
} from './one-password-item-ops.js'

interface RetrieveSuccessResponse {
  value: string
}

interface WriteSuccessResponse {
  ok: true
}

interface FailureResponse {
  error: string
  code: string
}

const VALID_OPS = ['retrieve', 'store', 'delete'] as const
type WorkerOp = (typeof VALID_OPS)[number]

function isValidOp(value: string | undefined): value is WorkerOp {
  if (value === undefined) return false
  for (const op of VALID_OPS) {
    if (op === value) return true
  }
  return false
}

function writeRetrieveSuccess(value: string): void {
  const response: RetrieveSuccessResponse = { value }
  process.stdout.write(JSON.stringify(response))
}

function writeWriteSuccess(): void {
  const response: WriteSuccessResponse = { ok: true }
  process.stdout.write(JSON.stringify(response))
}

function writeFailure(error: string, code: string): void {
  const response: FailureResponse = { error, code }
  process.stdout.write(JSON.stringify(response))
}

/** Read all of stdin (UTF-8) into a single string. Used only for `store`. */
function readStdin(): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: string[] = []
    process.stdin.setEncoding('utf8')
    process.stdin.on('data', (chunk: string) => {
      chunks.push(chunk)
    })
    process.stdin.on('end', () => {
      resolve(chunks.join(''))
    })
    process.stdin.on('error', (err: unknown) => {
      reject(err instanceof Error ? err : new Error(String(err)))
    })
  })
}

/** Sentinel rejection used to distinguish a presence-timeout from any other createClient failure. */
class PresenceTimeoutSentinel extends Error {}

async function main(): Promise<void> {
  const [, , accountName, vaultId, secretId, opArg] = process.argv

  if (accountName === undefined || vaultId === undefined || secretId === undefined) {
    writeFailure('Worker invoked with missing arguments', 'INTERNAL')
    process.exit(1)
  }

  // Omitted op defaults to 'retrieve' (compatibility with parents that
  // predate the write path). A PRESENT but unrecognized op is a
  // parent/worker protocol mismatch — fail closed rather than silently
  // running the wrong operation.
  if (opArg !== undefined && !isValidOp(opArg)) {
    writeFailure(`Worker invoked with unknown operation: ${opArg}`, 'INTERNAL')
    process.exit(1)
  }
  const op: WorkerOp = isValidOp(opArg) ? opArg : 'retrieve'

  // The SDK is an optional peer dependency, loaded lazily so the worker only
  // requires it when a per-access operation actually runs. A genuine "module
  // not resolved" is reported with PLUGIN_NOT_FOUND (the parent maps it to a
  // typed PluginNotFoundError); a present-but-broken SDK surfaces its real
  // error instead of a misleading "not installed" message.
  // Type-only annotation (typeof import) keeps the load itself dynamic while
  // giving `sdk` a precise type instead of an implicit any.
  let sdk: typeof import('@1password/sdk')
  try {
    sdk = await import('@1password/sdk')
  } catch (err) {
    if (isModuleNotFoundError(err)) {
      writeFailure(SDK_NOT_INSTALLED_MESSAGE, 'PLUGIN_NOT_FOUND')
    } else {
      writeFailure(`Failed to load 1Password SDK: ${String(err)}`, 'INTERNAL')
    }
    process.exit(1)
  }
  const { createClient, DesktopAuth, DesktopSessionExpiredError, RateLimitExceededError } = sdk

  // `store` needs the secret value before touching the SDK at all, so a
  // stdin read failure never reaches the biometric prompt.
  let pendingSecret: string | undefined
  if (op === 'store') {
    try {
      pendingSecret = await readStdin()
    } catch (err) {
      writeFailure(`Failed to read secret value from stdin: ${String(err)}`, 'INTERNAL')
      process.exit(1)
    }
  }

  let client
  if (op === 'retrieve') {
    // Unchanged from before issue #211 — reads are a non-goal of that issue.
    try {
      client = await createClient({
        auth: new DesktopAuth(accountName),
        integrationName: INTEGRATION_NAME,
        integrationVersion: getIntegrationVersion(),
      })
    } catch (err) {
      if (err instanceof DesktopSessionExpiredError) {
        writeFailure('1Password session has expired', 'LOCKED')
      } else {
        writeFailure(`Authentication failed: ${String(err)}`, 'AUTH_DENIED')
      }
      process.exit(1)
    }
  } else {
    // `store`/`delete` are the new presence-covered write paths (#211): a
    // fresh client is required for every call, exactly like `retrieve`, but
    // the failure taxonomy differs because these calls only ever happen when
    // a fresh human action was demanded. The SDK exposes only
    // `DesktopSessionExpiredError` and `RateLimitExceededError` as typed
    // errors (see `@1password/sdk`'s `errors.d.ts`) — there is no distinct
    // "user cancelled the biometric prompt" error. A bounded race against
    // `PRESENCE_WRITE_TIMEOUT_MS` distinguishes "no action within the
    // window" (`PRESENCE_TIMEOUT`) from any other client-creation failure,
    // which is treated as the human declining the fresh action
    // (`PRESENCE_DECLINED`) rather than the generic `AUTH_DENIED` used for
    // reads, since a write only reaches this point because presence was
    // required.
    let timerId: ReturnType<typeof setTimeout> | undefined
    const timeoutPromise = new Promise<never>((_resolve, reject) => {
      timerId = setTimeout(() => {
        reject(new PresenceTimeoutSentinel('presence action timed out'))
      }, PRESENCE_WRITE_TIMEOUT_MS)
    })
    try {
      client = await Promise.race([
        createClient({
          auth: new DesktopAuth(accountName),
          integrationName: INTEGRATION_NAME,
          integrationVersion: getIntegrationVersion(),
        }),
        timeoutPromise,
      ])
    } catch (err) {
      if (err instanceof PresenceTimeoutSentinel) {
        writeFailure(
          `No fresh presence action within ${String(PRESENCE_WRITE_TIMEOUT_MS)}ms`,
          'PRESENCE_TIMEOUT',
        )
      } else if (err instanceof DesktopSessionExpiredError) {
        writeFailure('1Password session has expired', 'LOCKED')
      } else if (err instanceof RateLimitExceededError) {
        // Not a human declining anything — a service-side throttle. Reporting
        // it as PRESENCE_DECLINED would misdirect the user toward the prompt.
        writeFailure(`1Password rate limit exceeded: ${String(err)}`, 'INTERNAL')
      } else {
        writeFailure(`1Password presence action declined: ${String(err)}`, 'PRESENCE_DECLINED')
      }
      process.exit(1)
    } finally {
      if (timerId !== undefined) {
        clearTimeout(timerId)
      }
    }
  }

  if (op === 'store') {
    // `pendingSecret` is always set here — `op === 'store'` only when the
    // stdin read above succeeded (a failed read already exited above).
    try {
      await storeSecretItem(
        client,
        vaultId,
        secretId,
        pendingSecret ?? '',
        sdk.ItemCategory.Password,
        sdk.ItemFieldType.Concealed,
      )
    } catch (err) {
      writeFailure(`Failed to store item: ${String(err)}`, 'INTERNAL')
      process.exit(1)
    }
    writeWriteSuccess()
    return
  }

  if (op === 'delete') {
    let deleted: boolean
    try {
      deleted = await deleteSecretItem(client, vaultId, secretId)
    } catch (err) {
      writeFailure(`Failed to delete item: ${String(err)}`, 'INTERNAL')
      process.exit(1)
      return
    }
    if (!deleted) {
      writeFailure(`Secret not found: ${secretId}`, 'NOT_FOUND')
      process.exit(1)
    }
    writeWriteSuccess()
    return
  }

  // op === 'retrieve' — unchanged read path.
  let overviews
  try {
    overviews = await client.items.list(vaultId)
  } catch (err) {
    writeFailure(`Failed to list items: ${String(err)}`, 'INTERNAL')
    process.exit(1)
  }

  let targetId: string | undefined
  for (const overview of overviews) {
    if (overview.title === secretId && overview.tags.includes(TAG)) {
      targetId = overview.id
      break
    }
  }

  if (targetId === undefined) {
    writeFailure(`Secret not found: ${secretId}`, 'NOT_FOUND')
    process.exit(1)
  }

  let item
  try {
    item = await client.items.get(vaultId, targetId)
  } catch (err) {
    writeFailure(`Failed to retrieve item: ${String(err)}`, 'NOT_FOUND')
    process.exit(1)
  }

  let secretValue: string | undefined
  for (const field of item.fields) {
    if (field.title === PASSWORD_FIELD_TITLE) {
      secretValue = field.value
      break
    }
  }

  if (secretValue === undefined) {
    writeFailure(`Item found but missing password field: ${secretId}`, 'NOT_FOUND')
    process.exit(1)
  }

  writeRetrieveSuccess(secretValue)
}

main().catch((err: unknown) => {
  writeFailure(`Unexpected worker error: ${String(err)}`, 'INTERNAL')
  process.exit(1)
})
