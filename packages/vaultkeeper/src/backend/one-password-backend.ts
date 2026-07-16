/**
 * 1Password SDK-based backend implementation.
 *
 * @remarks
 * Stores secrets in 1Password using the `@1password/sdk` package.
 * Each secret is stored as a "Password" item in the specified vault.
 *
 * Supports two access modes:
 * - `session`: A single SDK client is created on first use and cached for all operations.
 * - `per-access`: Every keyed operation (`retrieve()`, `store()`, `delete()`) spawns a child
 *   process that creates a fresh SDK client (triggering biometric auth) for that single
 *   operation. `exists()`/`list()` still use the cached session client — they are read-only
 *   probes, not the presence-gated path.
 *
 * Presence-per-use follows directly from this: in `per-access` mode the instance forces a
 * fresh biometric for `read`, `store`, and `delete`, so {@link OnePasswordBackend.getCapabilities}
 * reports `presencePerUse: true` scoped to `presenceEnforcedOperations: ['read', 'store', 'delete']`.
 * `session` mode reports `false`.
 *
 * @see https://github.com/mike-north/vaultkeeper/issues/211
 */

import { spawn } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import {
  SecretNotFoundError,
  PluginNotFoundError,
  BackendLockedError,
  BackendUnavailableError,
  AuthorizationDeniedError,
  ConfigValidationError,
  PresenceDeclinedError,
  PresenceTimeoutError,
} from '../errors.js'
import type { ListableBackend, PresenceCapableBackend, BackendCapabilities } from './types.js'
import {
  TAG,
  findItemOverviewByTitle,
  findItemByTitle,
  extractPasswordField,
  storeSecretItem,
  deleteSecretItem,
} from './one-password-item-ops.js'

// ---- SDK type imports (runtime-dynamic, not static imports) ----
// We import the SDK dynamically so that the backend degrades gracefully
// when the native SDK library is not available on the host system.

type SdkModule = typeof import('@1password/sdk')
type Client = import('@1password/sdk').Client

const SESSION_TIMEOUT_MS = 30_000
import {
  INTEGRATION_NAME,
  SDK_INSTALL_URL,
  SDK_NOT_INSTALLED_MESSAGE,
  SDK_PACKAGE,
  PRESENCE_WRITE_TIMEOUT_MS,
  getIntegrationVersion,
  isModuleNotFoundError,
} from './one-password-constants.js'

/** Options accepted by `OnePasswordBackend`. */
export interface OnePasswordBackendOptions {
  /** Vault ID to store/retrieve secrets from. */
  vault: string
  /** Account name or UUID for desktop app authentication (mutually exclusive with serviceAccountToken). */
  account?: string
  /** Service account token for headless CI/CD use (mutually exclusive with account). */
  serviceAccountToken?: string
  /** Access mode: 'session' (default) or 'per-access'. */
  accessMode?: 'session' | 'per-access'
  /**
   * Override the session timeout in milliseconds.
   * Defaults to 30000ms. Exposed for testing only.
   * @internal
   */
  sessionTimeoutMs?: number
}

/** Worker response shape for successful retrieval. */
interface WorkerSuccess {
  value: string
}

/** Worker response shape for a retrieval failure. */
interface WorkerFailure {
  error: string
  code: string
}

type WorkerResponse = WorkerSuccess | WorkerFailure

function isWorkerSuccess(res: WorkerResponse): res is WorkerSuccess {
  return 'value' in res
}

function isWorkerResponse(value: unknown): value is WorkerResponse {
  if (value === null || typeof value !== 'object') return false
  if ('value' in value && typeof value.value === 'string') return true
  if (
    'error' in value &&
    typeof value.error === 'string' &&
    'code' in value &&
    typeof value.code === 'string'
  )
    return true
  return false
}

/** Worker response shape for a successful `store`/`delete` (no value to report). */
interface WorkerWriteSuccess {
  ok: true
}

type WorkerWriteResponse = WorkerWriteSuccess | WorkerFailure

function isWorkerWriteSuccess(res: WorkerWriteResponse): res is WorkerWriteSuccess {
  // Check the VALUE, not just key presence: a malformed/buggy worker response
  // like `{ ok: false, error, code }` passes isWorkerWriteResponse via its
  // failure branch and must never be classified as a successful write.
  const record: Record<string, unknown> = { ...res }
  return record.ok === true
}

function isWorkerWriteResponse(value: unknown): value is WorkerWriteResponse {
  if (value === null || typeof value !== 'object') return false
  if ('ok' in value && value.ok === true) return true
  if (
    'error' in value &&
    typeof value.error === 'string' &&
    'code' in value &&
    typeof value.code === 'string'
  )
    return true
  return false
}

/**
 * 1Password backend via the `@1password/sdk` package.
 *
 * @remarks
 * Requires the `@1password/sdk` package to be installed and, when using desktop
 * authentication, the 1Password desktop application to be running and unlocked.
 *
 * @internal
 */
export class OnePasswordBackend implements ListableBackend, PresenceCapableBackend {
  readonly type = '1password'
  readonly displayName = '1Password'

  private readonly vaultId: string
  private readonly account: string | undefined
  private readonly serviceAccountToken: string | undefined
  private readonly accessMode: 'session' | 'per-access'
  private readonly sessionTimeoutMs: number

  /** In-flight or resolved client promise — prevents duplicate createClient calls. */
  private clientPromise: Promise<Client> | undefined

  constructor(options: OnePasswordBackendOptions) {
    if (options.accessMode === 'per-access' && options.serviceAccountToken !== undefined) {
      throw new ConfigValidationError(
        'per-access mode requires desktop biometric authentication and cannot be used with a service account token',
        'options.accessMode',
      )
    }
    if (options.account !== undefined && options.serviceAccountToken !== undefined) {
      throw new ConfigValidationError(
        'account and serviceAccountToken are mutually exclusive — provide one or the other, not both',
        'options.serviceAccountToken',
      )
    }
    this.vaultId = options.vault
    this.sessionTimeoutMs = options.sessionTimeoutMs ?? SESSION_TIMEOUT_MS
    if (options.account !== undefined) {
      this.account = options.account
    }
    if (options.serviceAccountToken !== undefined) {
      this.serviceAccountToken = options.serviceAccountToken
    }
    this.accessMode = options.accessMode ?? 'session'
  }

  async isAvailable(): Promise<boolean> {
    const sdk = await this.tryLoadSdk()
    return sdk !== null
  }

  /**
   * Report this instance's capabilities.
   *
   * @remarks
   * `presencePerUse` is `true` only in `per-access` mode, where every keyed
   * operation (`retrieve()`, `store()`, `delete()`) spawns a fresh worker
   * process that creates a new SDK client and triggers a per-operation
   * biometric approval that cannot be satisfied from the cached session
   * client. In the default `session` mode a single client is cached for all
   * operations, so operations ride one earlier unlock — that mode reports
   * `false`.
   *
   * **Operation coverage:** the per-access biometric path gates `retrieve()`,
   * `store()`, and `delete()` — every keyed operation reachable from
   * `presenceEnforcedOperations`. `exists()`/`list()` are read-only probes,
   * not keyed operations the presence contract covers, so they continue to
   * use the cached session client. This reports
   * `presenceEnforcedOperations: ['read', 'store', 'delete']` (issue #211
   * closed the earlier `store`/`delete` gap — see
   * {@link https://github.com/mike-north/vaultkeeper/issues/211}).
   *
   * **Truth-basis / cached-OS-unlock caveat:** even for a covered operation
   * the fresh action is "a fresh SDK client plus whatever the OS enforces at
   * that moment" — a "fresh process/SDK client" is **not** the same as a
   * guaranteed fresh hardware action. A per-access call can still ride a
   * cached OS-level Touch ID / Windows Hello unlock if the OS does not
   * re-prompt. The strongest per-use hardware guarantee comes from a touch
   * device (YubiKey / gpg smartcard).
   */
  getCapabilities(): Promise<BackendCapabilities> {
    if (this.accessMode === 'per-access') {
      return Promise.resolve({
        presencePerUse: true,
        presenceEnforcedOperations: ['read', 'store', 'delete'],
      })
    }
    return Promise.resolve({ presencePerUse: false })
  }

  // ---- Session client management ----

  /**
   * Dynamically import the SDK. Returns `null` if the SDK is not installed or
   * the native library cannot be loaded. Used by {@link isAvailable}, which
   * only needs a yes/no answer; call {@link loadSdkOrThrow} on paths that must
   * report *why* the SDK could not be loaded.
   */
  private async tryLoadSdk(): Promise<SdkModule | null> {
    try {
      const sdk = await import('@1password/sdk')
      return sdk
    } catch {
      return null
    }
  }

  /**
   * Dynamically import the SDK, throwing a typed {@link PluginNotFoundError}
   * only when the module cannot be resolved (the optional peer is not
   * installed). A present-but-broken SDK (native binding failure, init throw,
   * incompatible Node) surfaces its real error instead of a misleading
   * "not installed" message.
   */
  private async loadSdkOrThrow(): Promise<SdkModule> {
    try {
      return await import('@1password/sdk')
    } catch (error: unknown) {
      if (isModuleNotFoundError(error)) {
        throw new PluginNotFoundError(SDK_NOT_INSTALLED_MESSAGE, SDK_PACKAGE, SDK_INSTALL_URL)
      }
      throw error
    }
  }

  /**
   * Acquire (or create) a cached SDK client.
   * Wraps `createClient` with a configurable timeout (default 30 s) to handle
   * the known beta SDK hang after session expiry.
   */
  private acquireClient(): Promise<Client> {
    this.clientPromise ??= this.createClientInternal().catch((err: unknown) => {
      // Reset the promise so future calls retry
      this.clientPromise = undefined
      throw err
    })
    return this.clientPromise
  }

  private async createClientInternal(): Promise<Client> {
    const sdk = await this.loadSdkOrThrow()

    const auth = this.buildAuth(sdk)

    let timerId: ReturnType<typeof setTimeout> | undefined
    const timeoutPromise = new Promise<never>((_resolve, reject) => {
      timerId = setTimeout(() => {
        reject(
          new BackendLockedError('1Password session timed out waiting for authentication', true),
        )
      }, this.sessionTimeoutMs)
    })

    try {
      const client = await Promise.race([
        sdk.createClient({
          auth,
          integrationName: INTEGRATION_NAME,
          integrationVersion: getIntegrationVersion(),
        }),
        timeoutPromise,
      ])
      return client
    } catch (err) {
      if (err instanceof BackendLockedError) {
        throw err
      }
      if (err instanceof sdk.DesktopSessionExpiredError) {
        throw new BackendLockedError('1Password session has expired. Please unlock the app.', true)
      }
      throw new AuthorizationDeniedError(`1Password authentication failed: ${String(err)}`)
    } finally {
      if (timerId !== undefined) {
        clearTimeout(timerId)
      }
    }
  }

  private buildAuth(sdk: SdkModule): string | import('@1password/sdk').DesktopAuth {
    if (this.serviceAccountToken !== undefined) {
      return this.serviceAccountToken
    }
    const accountName = this.account ?? ''
    return new sdk.DesktopAuth(accountName)
  }

  // ---- SecretBackend / ListableBackend implementation ----

  async store(id: string, secret: string): Promise<void> {
    if (this.accessMode === 'per-access') {
      return this.writeViaWorker('store', id, secret)
    }
    const { ItemCategory, ItemFieldType } = await this.requireSdk()
    const client = await this.acquireClient()
    await storeSecretItem(
      client,
      this.vaultId,
      id,
      secret,
      ItemCategory.Password,
      ItemFieldType.Concealed,
    )
  }

  async retrieve(id: string): Promise<string> {
    if (this.accessMode === 'per-access') {
      return this.retrieveViaWorker(id)
    }
    return this.retrieveViaSession(id)
  }

  private async retrieveViaSession(id: string): Promise<string> {
    const client = await this.acquireClient()
    const item = await findItemByTitle(client, this.vaultId, id)
    if (item === undefined) {
      throw new SecretNotFoundError(`Secret not found in 1Password: ${id}`)
    }
    const value = extractPasswordField(item)
    if (value === undefined) {
      throw new SecretNotFoundError(`Secret found in 1Password but missing password field: ${id}`)
    }
    return value
  }

  /**
   * Spawn the per-access worker script that triggers a fresh biometric prompt
   * for each retrieval, then returns the secret from its stdout.
   */
  private retrieveViaWorker(id: string): Promise<string> {
    return new Promise((resolve, reject) => {
      const workerPath = join(dirname(fileURLToPath(import.meta.url)), 'one-password-worker.js')

      const accountArg = this.account ?? ''
      const child = spawn(process.execPath, [workerPath, accountArg, this.vaultId, id], {
        stdio: ['ignore', 'pipe', 'pipe'],
      })

      const stdoutChunks: Buffer[] = []
      const stderrChunks: Buffer[] = []
      child.stdout.on('data', (chunk: Buffer) => {
        stdoutChunks.push(chunk)
      })
      child.stderr.on('data', (chunk: Buffer) => {
        stderrChunks.push(chunk)
      })

      child.on('close', (code, signal) => {
        const raw = Buffer.concat(stdoutChunks).toString('utf8').trim()

        // If worker produced no stdout, use exit code + stderr for diagnostics
        if (raw === '') {
          const stderr = Buffer.concat(stderrChunks).toString('utf8').trim()
          const exitDescription =
            typeof signal === 'string'
              ? `terminated by signal ${signal}`
              : `exit code ${String(code)}`
          const detail = stderr !== '' ? stderr : exitDescription
          reject(
            new BackendUnavailableError(
              `1Password per-access worker crashed for secret ${id}: ${detail}`,
              'worker-crashed',
              ['1password'],
            ),
          )
          return
        }

        let parsed: unknown
        try {
          parsed = JSON.parse(raw)
        } catch {
          reject(new SecretNotFoundError(`Worker returned unparseable output for secret: ${id}`))
          return
        }
        if (!isWorkerResponse(parsed)) {
          reject(
            new SecretNotFoundError(`Worker returned unexpected response shape for secret: ${id}`),
          )
          return
        }
        if (isWorkerSuccess(parsed)) {
          resolve(parsed.value)
        } else {
          switch (parsed.code) {
            case 'PLUGIN_NOT_FOUND':
              reject(
                new PluginNotFoundError(SDK_NOT_INSTALLED_MESSAGE, SDK_PACKAGE, SDK_INSTALL_URL),
              )
              break
            case 'NOT_FOUND':
              reject(new SecretNotFoundError(`Secret not found in 1Password: ${id}`))
              break
            case 'AUTH_DENIED':
              reject(new AuthorizationDeniedError('1Password authentication was denied'))
              break
            case 'LOCKED':
              reject(new BackendLockedError('1Password is locked. Please unlock and retry.', true))
              break
            case 'INTERNAL':
              // A worker-internal failure (e.g. a present-but-broken SDK that
              // could not be loaded) is a backend problem, not a missing
              // secret — surface it as such with the worker's real detail so it
              // isn't misclassified as SecretNotFoundError.
              reject(
                new BackendUnavailableError(
                  `1Password per-access worker failed for secret ${id}: ${parsed.error}`,
                  'worker-internal-error',
                  ['1password'],
                ),
              )
              break
            default:
              reject(new SecretNotFoundError(`Worker failed for secret ${id}: ${parsed.error}`))
          }
        }
      })

      child.on('error', (err) => {
        reject(
          new BackendUnavailableError(
            `Failed to spawn 1Password per-access worker at ${workerPath}: ${String(err)}`,
            'worker-spawn-failed',
            ['1password'],
          ),
        )
      })
    })
  }

  /**
   * Spawn the per-access worker script to perform a `store` or `delete`,
   * triggering a fresh biometric prompt for this single write (issue #211).
   *
   * @remarks
   * For `store`, `secret` is delivered to the worker over **stdin**, never
   * argv — it must never appear in a process listing, shell history, or log.
   * `delete` needs no payload, so no stdin is written and the worker's stdin
   * is left `'ignore'`d, mirroring the retrieve path's spawn options.
   */
  private writeViaWorker(op: 'store' | 'delete', id: string, secret?: string): Promise<void> {
    return new Promise((resolve, reject) => {
      const workerPath = join(dirname(fileURLToPath(import.meta.url)), 'one-password-worker.js')

      const accountArg = this.account ?? ''
      const needsStdin = secret !== undefined
      const child = spawn(process.execPath, [workerPath, accountArg, this.vaultId, id, op], {
        stdio: [needsStdin ? 'pipe' : 'ignore', 'pipe', 'pipe'],
      })

      if (needsStdin && child.stdin !== null) {
        // A worker that exits before draining stdin (e.g. a protocol
        // validation failure) makes this write raise EPIPE, which without a
        // handler becomes an unhandled 'error' event and crashes the parent.
        // The worker's own failure is already reported through the close
        // handler below, so the stream error itself is safe to swallow.
        child.stdin.on('error', () => {
          /* reported via the close handler */
        })
        child.stdin.write(secret, 'utf8')
        child.stdin.end()
      }

      const stdoutChunks: Buffer[] = []
      const stderrChunks: Buffer[] = []
      // The ternary in `stdio` above (rather than a fixed literal tuple) means
      // TS can't narrow `stdout`/`stderr` to non-null from `spawn`'s overloads
      // — both are always piped regardless, so optional chaining here mirrors
      // the same null-safety idiom `execCommandFull` already uses in `util/exec.ts`.
      child.stdout?.on('data', (chunk: Buffer) => {
        stdoutChunks.push(chunk)
      })
      child.stderr?.on('data', (chunk: Buffer) => {
        stderrChunks.push(chunk)
      })

      child.on('close', (code, signal) => {
        const raw = Buffer.concat(stdoutChunks).toString('utf8').trim()

        if (raw === '') {
          const stderr = Buffer.concat(stderrChunks).toString('utf8').trim()
          // A signal-terminated worker reports code null — name the signal
          // instead of an unhelpful 'exit code null'.
          const exitDescription =
            typeof signal === 'string'
              ? `terminated by signal ${signal}`
              : `exit code ${String(code)}`
          const detail = stderr !== '' ? stderr : exitDescription
          reject(
            new BackendUnavailableError(
              `1Password per-access worker crashed during ${op} of secret ${id}: ${detail}`,
              'worker-crashed',
              ['1password'],
            ),
          )
          return
        }

        let parsed: unknown
        try {
          parsed = JSON.parse(raw)
        } catch {
          reject(
            new BackendUnavailableError(
              `Worker returned unparseable output during ${op} of secret ${id}`,
              'worker-internal-error',
              ['1password'],
            ),
          )
          return
        }
        if (!isWorkerWriteResponse(parsed)) {
          reject(
            new BackendUnavailableError(
              `Worker returned unexpected response shape during ${op} of secret ${id}`,
              'worker-internal-error',
              ['1password'],
            ),
          )
          return
        }
        if (isWorkerWriteSuccess(parsed)) {
          resolve()
          return
        }
        switch (parsed.code) {
          case 'PLUGIN_NOT_FOUND':
            reject(new PluginNotFoundError(SDK_NOT_INSTALLED_MESSAGE, SDK_PACKAGE, SDK_INSTALL_URL))
            break
          case 'NOT_FOUND':
            reject(new SecretNotFoundError(`Secret not found in 1Password: ${id}`))
            break
          case 'LOCKED':
            reject(new BackendLockedError('1Password is locked. Please unlock and retry.', true))
            break
          case 'PRESENCE_DECLINED':
            reject(
              new PresenceDeclinedError(
                `1Password ${op} presence action was declined for secret ${id}`,
                '1password',
              ),
            )
            break
          case 'PRESENCE_TIMEOUT':
            reject(
              new PresenceTimeoutError(
                `1Password ${op} presence action timed out for secret ${id}`,
                '1password',
                PRESENCE_WRITE_TIMEOUT_MS,
              ),
            )
            break
          case 'INTERNAL':
            reject(
              new BackendUnavailableError(
                `1Password per-access worker failed during ${op} of secret ${id}: ${parsed.error}`,
                'worker-internal-error',
                ['1password'],
              ),
            )
            break
          default:
            reject(
              new BackendUnavailableError(
                `Worker failed during ${op} of secret ${id}: ${parsed.error}`,
                'worker-internal-error',
                ['1password'],
              ),
            )
        }
      })

      child.on('error', (err) => {
        reject(
          new BackendUnavailableError(
            `Failed to spawn 1Password per-access worker at ${workerPath}: ${String(err)}`,
            'worker-spawn-failed',
            ['1password'],
          ),
        )
      })
    })
  }

  async delete(id: string): Promise<void> {
    if (this.accessMode === 'per-access') {
      return this.writeViaWorker('delete', id)
    }
    const client = await this.acquireClient()
    const deleted = await deleteSecretItem(client, this.vaultId, id)
    if (!deleted) {
      throw new SecretNotFoundError(`Secret not found in 1Password: ${id}`)
    }
  }

  async exists(id: string): Promise<boolean> {
    const client = await this.acquireClient()
    const overview = await findItemOverviewByTitle(client, this.vaultId, id)
    return overview !== undefined
  }

  async list(): Promise<string[]> {
    const client = await this.acquireClient()
    const overviews = await client.items.list(this.vaultId)
    const ids: string[] = []
    for (const overview of overviews) {
      if (overview.tags.includes(TAG)) {
        ids.push(overview.title)
      }
    }
    return ids
  }

  // ---- Private helpers ----

  /**
   * Load SDK, throwing a typed {@link PluginNotFoundError} when it is not
   * installed and surfacing the real error when it is present but broken.
   */
  private requireSdk(): Promise<SdkModule> {
    return this.loadSdkOrThrow()
  }
}
