/**
 * A mock presence-per-use backend for exercising the require-presence-per-use
 * enforcement path in-process.
 *
 * @remarks
 * Models a touch/biometric device: the configured instance is presence-per-use
 * capable, and every *keyed* operation (`store`/`retrieve`/`delete`/`signWithKey`)
 * demands a **distinct, fresh** human action that must be primed with
 * {@link MockPresenceBackend.arm} beforehand. An unprimed demand raises a
 * {@link PresenceTimeoutError} (the device was ready, no action happened); a
 * demand primed to decline raises a {@link PresenceDeclinedError}. This is what
 * makes the non-bypassability guarantee testable: a second operation can never
 * ride the first's resolution, because each op consumes exactly one primed
 * action.
 *
 * `exists` is a probe (no keyed material), so it does not demand presence — this
 * mirrors real backends and lets precondition checks run without a touch.
 * `generateSigningKey`/`getPublicKey` are enrollment/inspection, not the gated
 * operation, so they also do not demand presence; only `signWithKey` does.
 */

import * as crypto from 'node:crypto'
import type {
  SigningBackend,
  PresenceCapableBackend,
  BackendCapabilities,
} from '../../src/backend/types.js'
import type { SigningAlgorithm, SigningPublicKey } from '../../src/types.js'
import {
  PresenceDeclinedError,
  PresenceTimeoutError,
  SecretNotFoundError,
  SigningKeyNotFoundError,
  SigningKeyAlreadyExistsError,
  InvalidAlgorithmError,
} from '../../src/errors.js'

/** A scheduled human response to an upcoming fresh-presence demand. */
export type PresenceResponse = 'approve' | 'decline'

/** Options for {@link MockPresenceBackend}. */
export interface MockPresenceBackendOptions {
  /**
   * Whether this configured instance advertises `presencePerUse`. Defaults to
   * `true`. Set `false` to model a capable *type* configured in a non-capable
   * mode (its keyed operations then still demand a primed action, but
   * {@link MockPresenceBackend.getCapabilities} reports `false`, so the vault
   * refuses a require-presence operation before ever reaching them).
   */
  presencePerUse?: boolean
  /** Reported timeout for an unprimed presence demand. Defaults to 1000ms. */
  timeoutMs?: number
}

/** Signing algorithms this mock can generate keys for. */
const SUPPORTED_SIGNING_ALGORITHMS: readonly SigningAlgorithm[] = ['EdDSA']

function computeKid(spkiDer: Buffer): string {
  return crypto.createHash('sha256').update(spkiDer).digest('base64url')
}

export class MockPresenceBackend implements SigningBackend, PresenceCapableBackend {
  readonly type = 'mock-presence'
  readonly displayName = 'Mock Presence Backend'

  readonly #presencePerUse: boolean
  readonly #timeoutMs: number
  readonly #secrets = new Map<string, string>()
  readonly #signingKeys = new Map<string, crypto.KeyObject>()
  #armed: PresenceResponse[] = []

  /**
   * Number of times {@link MockPresenceBackend.getCapabilities} has been called.
   * Proves the vault queries capabilities fresh per operation (never caches).
   */
  getCapabilitiesCalls = 0

  /**
   * Number of distinct fresh-presence actions demanded by keyed operations.
   * Proves each operation drives its own fresh action.
   */
  freshActionDemands = 0

  constructor(options: MockPresenceBackendOptions = {}) {
    this.#presencePerUse = options.presencePerUse ?? true
    this.#timeoutMs = options.timeoutMs ?? 1000
  }

  /** Prime `count` upcoming fresh-presence demands with `response`. */
  arm(response: PresenceResponse = 'approve', count = 1): void {
    for (let i = 0; i < count; i++) {
      this.#armed.push(response)
    }
  }

  isAvailable(): Promise<boolean> {
    return Promise.resolve(true)
  }

  getCapabilities(): Promise<BackendCapabilities> {
    this.getCapabilitiesCalls++
    return Promise.resolve({ presencePerUse: this.#presencePerUse })
  }

  /**
   * Demand one distinct fresh human action, consuming a single primed response.
   * @throws {PresenceTimeoutError} If no action was primed.
   * @throws {PresenceDeclinedError} If the primed action was a decline.
   */
  #demandPresence(): void {
    this.freshActionDemands++
    const next = this.#armed.shift()
    if (next === undefined) {
      throw new PresenceTimeoutError(
        `No fresh presence action within ${String(this.#timeoutMs)}ms`,
        this.type,
        this.#timeoutMs,
      )
    }
    if (next === 'decline') {
      throw new PresenceDeclinedError('Human declined the fresh presence action', this.type)
    }
  }

  store(id: string, secret: string): Promise<void> {
    this.#demandPresence()
    this.#secrets.set(id, secret)
    return Promise.resolve()
  }

  retrieve(id: string): Promise<string> {
    this.#demandPresence()
    const value = this.#secrets.get(id)
    if (value === undefined) {
      return Promise.reject(new SecretNotFoundError(`Secret not found: ${id}`))
    }
    return Promise.resolve(value)
  }

  delete(id: string): Promise<void> {
    this.#demandPresence()
    this.#secrets.delete(id)
    return Promise.resolve()
  }

  exists(id: string): Promise<boolean> {
    return Promise.resolve(this.#secrets.has(id))
  }

  generateSigningKey(id: string, algorithm: SigningAlgorithm): Promise<void> {
    if (!SUPPORTED_SIGNING_ALGORITHMS.includes(algorithm)) {
      return Promise.reject(
        new InvalidAlgorithmError(`Unsupported algorithm: ${algorithm}`, algorithm, [
          ...SUPPORTED_SIGNING_ALGORITHMS,
        ]),
      )
    }
    if (this.#signingKeys.has(id)) {
      return Promise.reject(
        new SigningKeyAlreadyExistsError(`Signing key already exists: ${id}`, id),
      )
    }
    const { privateKey } = crypto.generateKeyPairSync('ed25519')
    this.#signingKeys.set(id, privateKey)
    return Promise.resolve()
  }

  getPublicKey(id: string): Promise<SigningPublicKey> {
    const privateKey = this.#signingKeys.get(id)
    if (privateKey === undefined) {
      return Promise.reject(new SigningKeyNotFoundError(`Signing key not found: ${id}`, id))
    }
    const publicKey = crypto.createPublicKey(privateKey)
    const spkiDer = publicKey.export({ type: 'spki', format: 'der' })
    const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }).toString()
    return Promise.resolve({
      publicKeyPem,
      algorithm: 'EdDSA',
      kid: computeKid(spkiDer),
    })
  }

  signWithKey(id: string, data: Buffer): Promise<Buffer> {
    const privateKey = this.#signingKeys.get(id)
    if (privateKey === undefined) {
      return Promise.reject(new SigningKeyNotFoundError(`Signing key not found: ${id}`, id))
    }
    // The fresh human action is demanded as part of the sign round-trip itself,
    // exactly as a touch device taps per signature (issue #122 AC7).
    this.#demandPresence()
    return Promise.resolve(crypto.sign(null, data, privateKey))
  }
}
