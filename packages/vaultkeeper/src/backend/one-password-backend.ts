/**
 * 1Password SDK-based backend implementation.
 *
 * @remarks
 * Stores secrets in 1Password using the `@1password/sdk` package.
 * Each secret is stored as a "Password" item in the specified vault.
 *
 * Supports two access modes:
 * - `session`: A single SDK client is created on first use and cached for all operations.
 * - `per-access`: The `retrieve()` operation spawns a child process that creates a fresh
 *   SDK client (triggering biometric auth) for each retrieval. Other operations still use
 *   the cached session client.
 */

import { spawn } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import {
  SecretNotFoundError,
  PluginNotFoundError,
  BackendLockedError,
  AuthorizationDeniedError,
} from '../errors.js'
import type { ListableBackend } from './types.js'

// ---- SDK type imports (runtime-dynamic, not static imports) ----
// We import the SDK dynamically so that the backend degrades gracefully
// when the native SDK library is not available on the host system.

type SdkModule = typeof import('@1password/sdk')
type Client = import('@1password/sdk').Client
type Item = import('@1password/sdk').Item
type ItemOverview = import('@1password/sdk').ItemOverview

const SDK_INSTALL_URL = 'https://developer.1password.com/docs/sdks/'
const TAG = 'vaultkeeper'
const PASSWORD_FIELD_TITLE = 'password'
const SESSION_TIMEOUT_MS = 30_000
const INTEGRATION_NAME = 'vaultkeeper'
// Keep in sync with the version in packages/vaultkeeper/package.json
const INTEGRATION_VERSION = '0.4.0'

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

/**
 * 1Password backend via the `@1password/sdk` package.
 *
 * @remarks
 * Requires the `@1password/sdk` package to be installed and, when using desktop
 * authentication, the 1Password desktop application to be running and unlocked.
 *
 * @internal
 */
export class OnePasswordBackend implements ListableBackend {
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
      throw new Error(
        'per-access mode requires desktop biometric authentication and cannot be used with a service account token',
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

  // ---- Session client management ----

  /**
   * Dynamically import the SDK. Returns `null` if the SDK is not installed or
   * the native library cannot be loaded.
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
    const sdk = await this.tryLoadSdk()
    if (sdk === null) {
      throw new PluginNotFoundError(
        '1Password SDK (@1password/sdk) is not available. Install it to use this backend.',
        '@1password/sdk',
        SDK_INSTALL_URL,
      )
    }

    const auth = this.buildAuth(sdk)

    let timerId: ReturnType<typeof setTimeout> | undefined
    const timeoutPromise = new Promise<never>((_resolve, reject) => {
      timerId = setTimeout(() => {
        reject(new BackendLockedError('1Password session timed out waiting for authentication', true))
      }, this.sessionTimeoutMs)
    })

    try {
      const client = await Promise.race([
        sdk.createClient({
          auth,
          integrationName: INTEGRATION_NAME,
          integrationVersion: INTEGRATION_VERSION,
        }),
        timeoutPromise,
      ])
      return client
    } catch (err) {
      if (err instanceof BackendLockedError) {
        throw err
      }
      if (err instanceof sdk.DesktopSessionExpiredError) {
        throw new BackendLockedError(
          '1Password session has expired. Please unlock the app.',
          true,
        )
      }
      throw new AuthorizationDeniedError(
        `1Password authentication failed: ${String(err)}`,
      )
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

  // ---- Helpers for item lookup by title ----

  /**
   * List all items in the vault tagged "vaultkeeper" and find one with the
   * matching title (= secret ID). Returns `undefined` if not found.
   */
  private async findItemOverview(
    client: Client,
    id: string,
  ): Promise<ItemOverview | undefined> {
    const overviews = await client.items.list(this.vaultId)
    for (const overview of overviews) {
      if (overview.title === id && overview.tags.includes(TAG)) {
        return overview
      }
    }
    return undefined
  }

  /**
   * Fetch the full item for a given secret id. Returns `undefined` if not found.
   */
  private async findItem(client: Client, id: string): Promise<Item | undefined> {
    const overview = await this.findItemOverview(client, id)
    if (overview === undefined) return undefined
    return client.items.get(this.vaultId, overview.id)
  }

  /**
   * Extract the concealed password field value from an item.
   */
  private extractSecret(item: Item, id: string): string {
    for (const field of item.fields) {
      if (field.title === PASSWORD_FIELD_TITLE) {
        return field.value
      }
    }
    throw new SecretNotFoundError(
      `Secret found in 1Password but missing password field: ${id}`,
    )
  }

  // ---- SecretBackend / ListableBackend implementation ----

  async store(id: string, secret: string): Promise<void> {
    const { ItemCategory, ItemFieldType } = await this.requireSdk()
    const client = await this.acquireClient()

    const existing = await this.findItem(client, id)

    if (existing !== undefined) {
      // Update the existing item's password field in-place
      const updatedFields = existing.fields.map((f) => {
        if (f.title === PASSWORD_FIELD_TITLE) {
          return { ...f, value: secret }
        }
        return f
      })
      await client.items.put({ ...existing, fields: updatedFields })
    } else {
      await client.items.create({
        category: ItemCategory.Password,
        vaultId: this.vaultId,
        title: id,
        tags: [TAG],
        fields: [
          {
            id: 'password',
            title: PASSWORD_FIELD_TITLE,
            fieldType: ItemFieldType.Concealed,
            value: secret,
          },
        ],
      })
    }
  }

  async retrieve(id: string): Promise<string> {
    if (this.accessMode === 'per-access') {
      return this.retrieveViaWorker(id)
    }
    return this.retrieveViaSession(id)
  }

  private async retrieveViaSession(id: string): Promise<string> {
    const client = await this.acquireClient()
    const item = await this.findItem(client, id)
    if (item === undefined) {
      throw new SecretNotFoundError(`Secret not found in 1Password: ${id}`)
    }
    return this.extractSecret(item, id)
  }

  /**
   * Spawn the per-access worker script that triggers a fresh biometric prompt
   * for each retrieval, then returns the secret from its stdout.
   */
  private retrieveViaWorker(id: string): Promise<string> {
    return new Promise((resolve, reject) => {
      const workerPath = join(
        dirname(fileURLToPath(import.meta.url)),
        'one-password-worker.js',
      )

      const accountArg = this.account ?? ''
      const child = spawn(
        process.execPath,
        [workerPath, accountArg, this.vaultId, id],
        { stdio: ['ignore', 'pipe', 'ignore'] },
      )

      const chunks: Buffer[] = []
      child.stdout.on('data', (chunk: Buffer) => {
        chunks.push(chunk)
      })

      child.on('close', () => {
        const raw = Buffer.concat(chunks).toString('utf8').trim()
        let parsed: unknown
        try {
          parsed = JSON.parse(raw)
        } catch {
          reject(new SecretNotFoundError(`Worker returned unparseable output for secret: ${id}`))
          return
        }
        if (!isWorkerResponse(parsed)) {
          reject(new SecretNotFoundError(`Worker returned unexpected response shape for secret: ${id}`))
          return
        }
        if (isWorkerSuccess(parsed)) {
          resolve(parsed.value)
        } else {
          switch (parsed.code) {
            case 'NOT_FOUND':
              reject(new SecretNotFoundError(`Secret not found in 1Password: ${id}`))
              break
            case 'AUTH_DENIED':
              reject(new AuthorizationDeniedError('1Password authentication was denied'))
              break
            case 'LOCKED':
              reject(new BackendLockedError('1Password is locked. Please unlock and retry.', true))
              break
            default:
              reject(new SecretNotFoundError(`Worker failed for secret ${id}: ${parsed.error}`))
          }
        }
      })

      child.on('error', (err) => {
        reject(new PluginNotFoundError(
          `Failed to spawn 1Password worker: ${String(err)}`,
          '@1password/sdk',
          SDK_INSTALL_URL,
        ))
      })
    })
  }

  async delete(id: string): Promise<void> {
    const client = await this.acquireClient()
    const overview = await this.findItemOverview(client, id)
    if (overview === undefined) {
      throw new SecretNotFoundError(`Secret not found in 1Password: ${id}`)
    }
    await client.items.delete(this.vaultId, overview.id)
  }

  async exists(id: string): Promise<boolean> {
    const client = await this.acquireClient()
    const overview = await this.findItemOverview(client, id)
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

  /** Load SDK and throw PluginNotFoundError if unavailable. */
  private async requireSdk(): Promise<SdkModule> {
    const sdk = await this.tryLoadSdk()
    if (sdk === null) {
      throw new PluginNotFoundError(
        '1Password SDK (@1password/sdk) is not available.',
        '@1password/sdk',
        SDK_INSTALL_URL,
      )
    }
    return sdk
  }
}
