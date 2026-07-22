/**
 * In-memory secret backend for testing.
 */

import * as crypto from 'node:crypto'
import type { Buffer } from 'node:buffer'
import type {
  ListableBackend,
  SigningBackend,
  PresenceCapableBackend,
  BackendCapabilities,
  SigningAlgorithm,
  SigningPublicKey,
} from 'vaultkeeper'
import {
  SecretNotFoundError,
  SigningKeyNotFoundError,
  SigningKeyAlreadyExistsError,
  InvalidAlgorithmError,
  BackendUnavailableError,
  AuthorizationDeniedError,
  BackendLockedError,
} from 'vaultkeeper'
import { FaultPlan } from './fault-plan.js'
import type { FaultMode, FaultOptions } from './fault-plan.js'

/** Signing algorithms this backend can generate keys for. */
const SUPPORTED_SIGNING_ALGORITHMS: readonly SigningAlgorithm[] = ['EdDSA']

/** In-memory record of an enrolled Ed25519 signing key. */
interface SigningKeyRecord {
  privateKey: crypto.KeyObject
  publicKey: crypto.KeyObject
}

/** Compute the stable kid for an SPKI-DER public key: base64url(sha256(der)). */
function computeKid(spkiDer: Buffer): string {
  return crypto.createHash('sha256').update(spkiDer).digest('base64url')
}

/**
 * The operations {@link InMemoryBackend.injectFault} can target. Matches the
 * methods of `SecretBackend` and `SigningBackend` that perform real work (a
 * fault is checked at the top of each, before any state is touched).
 *
 * @public
 */
export type InMemoryBackendFaultOperation =
  | 'store'
  | 'retrieve'
  | 'delete'
  | 'exists'
  | 'list'
  | 'generateSigningKey'
  | 'getPublicKey'
  | 'signWithKey'

const SIGNING_OPERATIONS: ReadonlySet<InMemoryBackendFaultOperation> = new Set([
  'generateSigningKey',
  'getPublicKey',
  'signWithKey',
])

/**
 * A fully in-memory `SecretBackend` for testing.
 *
 * @remarks
 * This backend stores secrets in a plain `Map` and has no external
 * dependencies. It is suitable for unit, integration, and e2e tests. It also
 * implements `SigningBackend` (real in-memory Ed25519 keys — the private key
 * never leaves the backend) and `PresenceCapableBackend` (reports no presence
 * by default), and offers deterministic per-operation fault injection via
 * {@link InMemoryBackend.injectFault} for exercising a consumer's
 * error-handling paths without hardware.
 *
 * @public
 */
export class InMemoryBackend implements ListableBackend, SigningBackend, PresenceCapableBackend {
  readonly type = 'memory'
  readonly displayName = 'In-Memory Backend'
  readonly #store = new Map<string, string>()
  readonly #signingKeys = new Map<string, SigningKeyRecord>()
  readonly #faultPlan = new FaultPlan<InMemoryBackendFaultOperation>()

  /** @public */
  isAvailable(): Promise<boolean> {
    return Promise.resolve(true)
  }

  /** @public */
  store(id: string, secret: string): Promise<void> {
    try {
      this.#maybeThrowFault('store', id)
    } catch (err) {
      return Promise.reject(err instanceof Error ? err : new Error(String(err)))
    }
    this.#store.set(id, secret)
    return Promise.resolve()
  }

  /** @public */
  retrieve(id: string): Promise<string> {
    try {
      this.#maybeThrowFault('retrieve', id)
    } catch (err) {
      return Promise.reject(err instanceof Error ? err : new Error(String(err)))
    }
    const val = this.#store.get(id)
    if (val === undefined) {
      return Promise.reject(new SecretNotFoundError(`Secret not found: ${id}`))
    }
    return Promise.resolve(val)
  }

  /** @public */
  delete(id: string): Promise<void> {
    try {
      this.#maybeThrowFault('delete', id)
    } catch (err) {
      return Promise.reject(err instanceof Error ? err : new Error(String(err)))
    }
    this.#store.delete(id)
    return Promise.resolve()
  }

  /** @public */
  exists(id: string): Promise<boolean> {
    try {
      this.#maybeThrowFault('exists', id)
    } catch (err) {
      return Promise.reject(err instanceof Error ? err : new Error(String(err)))
    }
    return Promise.resolve(this.#store.has(id))
  }

  /** @public */
  list(): Promise<string[]> {
    try {
      this.#maybeThrowFault('list')
    } catch (err) {
      return Promise.reject(err instanceof Error ? err : new Error(String(err)))
    }
    return Promise.resolve([...this.#store.keys()])
  }

  /**
   * Remove all stored secrets and signing keys, and disarm any armed faults.
   * Useful for full test teardown/reset between cases.
   * @public
   */
  clear(): void {
    this.#store.clear()
    this.#signingKeys.clear()
    this.#faultPlan.clearAll()
  }

  /**
   * The number of secrets currently stored.
   * @public
   */
  get size(): number {
    return this.#store.size
  }

  // --- PresenceCapableBackend ---

  /**
   * Report this instance's `BackendCapabilities`.
   *
   * @remarks
   * `InMemoryBackend` has no physical presence mechanism (no touch device, no
   * biometric prompt) — it always reports `presencePerUse: false`, expressed
   * in the same `BackendCapabilities` vocabulary every other backend uses, so
   * a `--require-presence-per-use` request against this double is correctly
   * refused with `NotCapableError` rather than silently satisfied.
   *
   * @public
   */
  getCapabilities(): Promise<BackendCapabilities> {
    return Promise.resolve({ presencePerUse: false })
  }

  // --- SigningBackend ---

  /** @public */
  generateSigningKey(id: string, algorithm: SigningAlgorithm): Promise<void> {
    try {
      this.#maybeThrowFault('generateSigningKey', id)
      if (!SUPPORTED_SIGNING_ALGORITHMS.includes(algorithm)) {
        throw new InvalidAlgorithmError(
          `Unsupported signing algorithm '${algorithm}'. Supported: ${SUPPORTED_SIGNING_ALGORITHMS.join(', ')}.`,
          algorithm,
          [...SUPPORTED_SIGNING_ALGORITHMS],
        )
      }
      if (this.#signingKeys.has(id)) {
        throw new SigningKeyAlreadyExistsError(`Signing key already exists: ${id}`, id)
      }
    } catch (err) {
      return Promise.reject(err instanceof Error ? err : new Error(String(err)))
    }
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519')
    this.#signingKeys.set(id, { privateKey, publicKey })
    return Promise.resolve()
  }

  /** @public */
  getPublicKey(id: string): Promise<SigningPublicKey> {
    let record: SigningKeyRecord
    try {
      this.#maybeThrowFault('getPublicKey', id)
      record = this.#requireSigningKey(id)
    } catch (err) {
      return Promise.reject(err instanceof Error ? err : new Error(String(err)))
    }
    const publicKeyPem = record.publicKey.export({ type: 'spki', format: 'pem' }).toString()
    const spkiDer = record.publicKey.export({ type: 'spki', format: 'der' })
    return Promise.resolve({
      publicKeyPem,
      algorithm: 'EdDSA',
      kid: computeKid(spkiDer),
    })
  }

  /** @public */
  signWithKey(id: string, data: Buffer): Promise<Buffer> {
    let record: SigningKeyRecord
    try {
      this.#maybeThrowFault('signWithKey', id)
      record = this.#requireSigningKey(id)
    } catch (err) {
      return Promise.reject(err instanceof Error ? err : new Error(String(err)))
    }
    // Ed25519: the algorithm is implicit in the key, so pass null.
    return Promise.resolve(crypto.sign(null, data, record.privateKey))
  }

  #requireSigningKey(id: string): SigningKeyRecord {
    const record = this.#signingKeys.get(id)
    if (record === undefined) {
      throw new SigningKeyNotFoundError(`Signing key not found: ${id}`, id)
    }
    return record
  }

  // --- Fault injection ---

  /**
   * Arm a deterministic fault for the next matching call to `operation`.
   *
   * @remarks
   * Faults are checked at the top of each backend method, before any real
   * state is read or written, and throw the **real typed error class** from
   * `vaultkeeper`'s hierarchy — never a stringly-typed lookalike — so a
   * consumer's `catch` block sees in tests exactly what it sees in
   * production. The mode-to-class mapping is fixed and deliberately narrow
   * (kept conservative rather than configurable, per stakeholder feedback on
   * an earlier prototype's fault-injection ergonomics):
   *
   * - `'backend-unavailable'` → `BackendUnavailableError` — the backend
   *   itself cannot be reached for this call.
   * - `'key-absent'` → `SigningKeyNotFoundError` for a signing operation that
   *   reads an existing key (`getPublicKey`, `signWithKey`), or
   *   `SecretNotFoundError` for a plain secret operation (`retrieve`,
   *   `delete`, `exists`) — signing keys and secrets are distinct namespaces
   *   with distinct "not found" types in the real hierarchy, so which one
   *   fires depends on which operation the fault targets. Both include the
   *   operation's `id` in their message. Arming `'key-absent'` against
   *   `'generateSigningKey'` is rejected at arm time (see `@throws` below):
   *   enrollment has no existing key to be "absent".
   * - `'permission-denied'` → `AuthorizationDeniedError` — the caller was
   *   denied authorization for this operation.
   * - `'session-expired'` → `BackendLockedError` (`interactive: true`) —
   *   models a real backend construct (a session that has gone stale and
   *   needs a fresh interactive unlock), which is what an "expired session"
   *   means at the backend boundary. `TokenExpiredError` was deliberately not
   *   used here: it signals a JWE token past its `exp` claim, an orthogonal
   *   JWE-lifecycle concept unrelated to backend session state.
   *
   * The scripting mechanics (arm/consume/clear) live in the reusable
   * {@link FaultPlan} helper this backend holds internally — it knows nothing
   * about `InMemoryBackend`'s storage, so a future backend-flavored double
   * (e.g. one faking a CLI-backed store) can consult the same mechanism.
   *
   * @param operation - The backend method to fault.
   * @param mode - Which typed error to throw when `operation` is next called.
   * @param options - `{ persistent: true }` to keep firing until
   *   {@link InMemoryBackend.clearFault} is called; omitted or
   *   `{ persistent: false }` (the default) fires once and then clears itself.
   * @throws {Error} If `mode` is `'key-absent'` and `operation` is
   *   `'generateSigningKey'` — enrollment has no existing key to be "absent",
   *   so this combination is a test-authoring mistake and is rejected at arm
   *   time rather than silently accepted and misreported later.
   * @public
   */
  injectFault(
    operation: InMemoryBackendFaultOperation,
    mode: FaultMode,
    options?: FaultOptions,
  ): void {
    if (mode === 'key-absent' && operation === 'generateSigningKey') {
      throw new Error(
        "Cannot inject 'key-absent' against 'generateSigningKey': enrollment has no existing " +
          "key to be absent. Use a different fault mode (e.g. 'backend-unavailable'), or target " +
          "an operation that reads an existing key ('getPublicKey', 'signWithKey').",
      )
    }
    this.#faultPlan.inject(operation, mode, options)
  }

  /**
   * Remove an armed fault for `operation`, if any. Safe to call when no fault
   * is armed.
   * @public
   */
  clearFault(operation: InMemoryBackendFaultOperation): void {
    this.#faultPlan.clear(operation)
  }

  /**
   * Remove all armed faults, regardless of mode or operation. Useful for test
   * teardown.
   * @public
   */
  clearAllFaults(): void {
    this.#faultPlan.clearAll()
  }

  #maybeThrowFault(operation: InMemoryBackendFaultOperation, id?: string): void {
    const mode = this.#faultPlan.consume(operation)
    if (mode === undefined) {
      return
    }
    throw this.#buildFaultError(operation, mode, id)
  }

  #buildFaultError(
    operation: InMemoryBackendFaultOperation,
    mode: FaultMode,
    id: string | undefined,
  ): Error {
    switch (mode) {
      case 'backend-unavailable':
        return new BackendUnavailableError(
          `Injected fault: backend unavailable during '${operation}'`,
          'fault-injected',
          [this.type],
        )
      case 'key-absent':
        if (SIGNING_OPERATIONS.has(operation)) {
          return new SigningKeyNotFoundError(
            `Injected fault: signing key not found during '${operation}'`,
            id ?? '(unknown)',
          )
        }
        return new SecretNotFoundError(
          `Injected fault: secret not found during '${operation}': ${id ?? '(unknown)'}`,
        )
      case 'permission-denied':
        return new AuthorizationDeniedError(
          `Injected fault: permission denied during '${operation}'`,
        )
      case 'session-expired':
        return new BackendLockedError(
          `Injected fault: backend session expired during '${operation}'`,
          true,
        )
    }
  }
}
