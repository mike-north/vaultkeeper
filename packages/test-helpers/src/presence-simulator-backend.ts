/**
 * A backend that scripts vaultkeeper's presence signal for tests. Deliberately
 * isolated from every production code path — see the class documentation for
 * the threat model and the three stacked guards that enforce the isolation.
 */

import type { Buffer } from 'node:buffer'
import type {
  ListableBackend,
  SigningBackend,
  PresenceCapableBackend,
  BackendCapabilities,
  PresenceOperation,
  SigningAlgorithm,
  SigningPublicKey,
} from 'vaultkeeper'
import { PresenceDeclinedError, PresenceTimeoutError, TestDoubleMisuseError } from 'vaultkeeper'
import { InMemoryBackend } from './in-memory-backend.js'

/**
 * The scriptable outcome for a single `PresenceOperation` against a
 * {@link PresenceSimulatorBackend}.
 *
 * @remarks
 * Expressed directly in the vault's own `BackendCapabilities` capability
 * vocabulary, not a parallel concept:
 *
 * - `'grant'` — this instance advertises presence for the operation (so the
 *   vault's fail-closed pre-check passes) and the operation itself succeeds,
 *   as if a fresh physical action (a touch, a tap, a biometric approval) had
 *   just been performed.
 * - `'refuse'` — this instance still advertises presence for the operation
 *   (the pre-check passes and the backend *is* touched), but the operation
 *   throws a `PresenceDeclinedError` — the human was asked and said no.
 * - `'timeout'` — this instance still advertises presence for the operation
 *   (the pre-check passes and the backend *is* touched), but the operation
 *   throws a `PresenceTimeoutError` — the device was present but no fresh
 *   action happened before the simulated wait elapsed.
 * - `'not-capable'` — this instance does not advertise presence for the
 *   operation at all. A `requirePresencePerUse` request is refused by the
 *   vault's own enforcement with a typed `NotCapableError`, **before** this
 *   backend is ever touched — the central negative case this class exists
 *   to make drivable in CI.
 *
 * @public
 */
export type PresenceSimulatorOutcome = 'grant' | 'refuse' | 'timeout' | 'not-capable'

/**
 * The one-shot outcome a test can arm for a single upcoming call to a
 * {@link PresenceSimulatorBackend} operation via {@link PresenceSimulatorBackend.armPresence}.
 *
 * @remarks
 * Excludes `'not-capable'`: arming an operation is itself the signal that the
 * operation is presence-covered for that call. To model an operation the
 * vault's own pre-check should refuse before the backend is touched, leave it
 * unarmed and unscripted (the default) instead.
 *
 * @public
 */
export type PresenceSimulatorArmedOutcome = Exclude<PresenceSimulatorOutcome, 'not-capable'>

/**
 * Per-operation outcome script for a {@link PresenceSimulatorBackend}. Any
 * operation left unspecified defaults to `'not-capable'` — absence, not
 * presence, is the safe default for a class whose entire point is making
 * absence provable.
 *
 * @public
 */
export interface PresenceSimulatorOperationOutcomes {
  /** Outcome for the `read` operation (the secret read behind `setup`/`exec`). */
  read?: PresenceSimulatorOutcome
  /** Outcome for the `store` operation. */
  store?: PresenceSimulatorOutcome
  /** Outcome for the `delete` operation. */
  delete?: PresenceSimulatorOutcome
  /** Outcome for the `sign` operation. */
  sign?: PresenceSimulatorOutcome
}

/**
 * Options accepted by {@link PresenceSimulatorBackend.forTesting}.
 * @public
 */
export interface PresenceSimulatorBackendOptions {
  /**
   * Per-operation outcome script. Any operation not listed defaults to
   * `'not-capable'`.
   */
  operations?: PresenceSimulatorOperationOutcomes
}

const ALL_OPERATIONS: readonly PresenceOperation[] = ['read', 'store', 'delete', 'sign']

/**
 * Resolve the outcome script, defaulting every unspecified operation to
 * `'not-capable'`.
 */
function resolveOutcomes(
  operations: PresenceSimulatorOperationOutcomes | undefined,
): Record<PresenceOperation, PresenceSimulatorOutcome> {
  return {
    read: operations?.read ?? 'not-capable',
    store: operations?.store ?? 'not-capable',
    delete: operations?.delete ?? 'not-capable',
    sign: operations?.sign ?? 'not-capable',
  }
}

/**
 * A presence forger for tests: a backend that lets a test script vaultkeeper's
 * presence signal on demand, including its absence.
 *
 * This class exists to make one property provable in CI: that an automation
 * signer attempting a presence-gated operation is refused. A backend that can
 * fabricate "presence was granted" on request is, by construction, exactly
 * the vulnerability presence-backed gates exist to prevent — a presence
 * simulator is a presence forger. If it were reachable from any production
 * code path, it would hand every consumer a presence bypass in exchange for
 * test convenience. That is the worst possible outcome, so this class is
 * unreachable from production through three independent, stacked guards, any
 * one of which would have to fail alongside the other two for a real
 * deployment to be affected:
 *
 * 1. Structural. This class lives only in the devDependency-only
 * `@vaultkeeper/test-helpers` package and is never registered with
 * vaultkeeper's backend registry. No `config.json` on any machine can name
 * it, so no production vault instance can ever load it. The only wiring path
 * is direct construction in test code.
 *
 * 2. Explicit acknowledgment. There is no default, public constructor. The
 * only construction path is the named opt-in `PresenceSimulatorBackend.forTesting(...)`,
 * so it can never be instantiated incidentally.
 *
 * 3. Loud tripwire. Construction throws — never warns, never degrades — when
 * `NODE_ENV` is `'production'`.
 *
 * Once constructed, its per-operation outcomes are scriptable across
 * `'grant'`, `'refuse'`, and `'not-capable'` (see
 * {@link PresenceSimulatorOutcome}), expressed in the vault's own
 * `BackendCapabilities` vocabulary. The negative case this class exists to
 * prove — an automation signer refused with a typed `NotCapableError` before
 * the backend is touched — falls out of vaultkeeper's own existing
 * fail-closed presence enforcement; this class only makes both sides of that
 * boundary drivable in CI, rather than simulating the refusal itself.
 *
 * The outcome vocabulary (`'grant'` / `'refuse'` / `'timeout'` / `'not-capable'`,
 * resolved into `presencePerUse`/`presenceEnforcedOperations`) is exactly the
 * existing `BackendCapabilities` vocabulary every real backend already
 * reports through — not a parallel concept invented for this class — so a
 * future backend-flavored double (e.g. a 1Password mock with
 * per-process-grant behavior) can reuse the same vocabulary rather than
 * inventing its own.
 *
 * Static per-operation scripting (via `forTesting({ operations })`) replays
 * the same outcome for every call, which cannot prove that presence is a
 * fresh, non-cacheable action demanded on *every* call rather than a
 * capability checked once and then assumed. For that, arm one-shot outcomes
 * with {@link PresenceSimulatorBackend.armPresence}: each call consumes
 * exactly one armed outcome, and a call against an operation with no armed
 * outcome left throws `PresenceTimeoutError` — mirroring the
 * arm-per-call/`PresenceTimeout` semantics of the Rust core's own
 * `MockPresenceBackend` (`crates/vaultkeeper-core/tests/presence_capability.rs`).
 * Arming an operation activates it for `getCapabilities()` regardless of its
 * static script.
 *
 * @public
 */
export class PresenceSimulatorBackend
  implements ListableBackend, SigningBackend, PresenceCapableBackend
{
  readonly type = 'presence-simulator'
  readonly displayName = 'Presence Simulator Backend (test-only)'
  readonly #delegate = new InMemoryBackend()
  readonly #outcomes: Record<PresenceOperation, PresenceSimulatorOutcome>
  readonly #queues: Partial<Record<PresenceOperation, PresenceSimulatorArmedOutcome[]>> = {}

  private constructor(outcomes: Record<PresenceOperation, PresenceSimulatorOutcome>) {
    this.#outcomes = outcomes
  }

  /**
   * The only construction path for {@link PresenceSimulatorBackend} — an
   * explicit, named opt-in (guard 2). Throws if `NODE_ENV` is `'production'`
   * (guard 3): construction of a presence forger must never silently succeed,
   * warn, or degrade in a production environment.
   *
   * @param options - Optional per-operation outcome script. Any operation not
   *   listed defaults to `'not-capable'`.
   * @returns A configured `PresenceSimulatorBackend` instance.
   * @throws A `TestDoubleMisuseError` if `process.env.NODE_ENV === 'production'`.
   * @public
   */
  static forTesting(options?: PresenceSimulatorBackendOptions): PresenceSimulatorBackend {
    const nodeEnv = process.env.NODE_ENV
    if (nodeEnv === 'production') {
      throw new TestDoubleMisuseError(
        'PresenceSimulatorBackend.forTesting() refused to construct: NODE_ENV is "production". ' +
          'This class fabricates vaultkeeper presence signals for tests and must never run in a ' +
          'production environment.',
        'PresenceSimulatorBackend',
        nodeEnv,
      )
    }
    return new PresenceSimulatorBackend(resolveOutcomes(options?.operations))
  }

  /**
   * Arm one one-shot outcome for the next call to `operation`. Each armed
   * outcome is consumed by exactly one call; a call against an operation
   * with no armed outcome remaining throws `PresenceTimeoutError`, modeling
   * an unprimed fresh-presence demand.
   *
   * @remarks
   * Arming an operation (even with an empty queue left after outcomes are
   * consumed) makes it presence-covered for {@link PresenceSimulatorBackend.getCapabilities},
   * independently of that operation's static `forTesting({ operations })`
   * script.
   *
   * @param operation - The operation to arm an outcome for.
   * @param outcome - The one-shot outcome the next call consumes.
   * @public
   */
  armPresence(operation: PresenceOperation, outcome: PresenceSimulatorArmedOutcome): void {
    const queue = this.#queues[operation]
    if (queue === undefined) {
      this.#queues[operation] = [outcome]
    } else {
      queue.push(outcome)
    }
  }

  /** @public */
  isAvailable(): Promise<boolean> {
    return this.#delegate.isAvailable()
  }

  /** @public */
  async store(id: string, secret: string): Promise<void> {
    this.#resolvePresence('store')
    return this.#delegate.store(id, secret)
  }

  /** @public */
  async retrieve(id: string): Promise<string> {
    this.#resolvePresence('read')
    return this.#delegate.retrieve(id)
  }

  /** @public */
  async delete(id: string): Promise<void> {
    this.#resolvePresence('delete')
    return this.#delegate.delete(id)
  }

  /** @public */
  exists(id: string): Promise<boolean> {
    return this.#delegate.exists(id)
  }

  /** @public */
  list(): Promise<string[]> {
    return this.#delegate.list()
  }

  // --- PresenceCapableBackend ---

  /**
   * Report this instance's scripted `BackendCapabilities`.
   *
   * @remarks
   * An operation reports as presence-covered (included in
   * `presenceEnforcedOperations`) when its static outcome is `'grant'`,
   * `'refuse'`, or `'timeout'`, or when it has ever been armed via
   * {@link PresenceSimulatorBackend.armPresence} — all mean this instance
   * *does* force a fresh per-use action for that operation. An operation
   * that is unarmed and scripted `'not-capable'` (the default) is omitted,
   * so vaultkeeper's own fail-closed enforcement refuses a
   * `requirePresencePerUse` request for it with `NotCapableError` before this
   * backend is ever touched. When every operation is unarmed and
   * `'not-capable'`, this reports `presencePerUse: false` outright.
   *
   * @public
   */
  getCapabilities(): Promise<BackendCapabilities> {
    const enforced = ALL_OPERATIONS.filter(
      (op) => this.#outcomes[op] !== 'not-capable' || this.#queues[op] !== undefined,
    )
    if (enforced.length === 0) {
      return Promise.resolve({ presencePerUse: false })
    }
    return Promise.resolve({ presencePerUse: true, presenceEnforcedOperations: enforced })
  }

  // --- SigningBackend ---

  /** @public */
  generateSigningKey(id: string, algorithm: SigningAlgorithm): Promise<void> {
    return this.#delegate.generateSigningKey(id, algorithm)
  }

  /** @public */
  getPublicKey(id: string): Promise<SigningPublicKey> {
    return this.#delegate.getPublicKey(id)
  }

  /** @public */
  async signWithKey(id: string, data: Buffer): Promise<Buffer> {
    this.#resolvePresence('sign')
    return this.#delegate.signWithKey(id, data)
  }

  /**
   * Resolve the presence outcome for one call to `operation` and throw the
   * matching typed error, if any.
   *
   * @remarks
   * When `operation` has an armed queue (via
   * {@link PresenceSimulatorBackend.armPresence}), this consumes exactly one
   * queued outcome; an empty queue (an unprimed demand) resolves to
   * `'timeout'`. Otherwise it falls back to the static `forTesting({
   * operations })` script. `'refuse'` throws `PresenceDeclinedError`,
   * `'timeout'` throws `PresenceTimeoutError`. `'grant'` (the operation
   * proceeds normally) and `'not-capable'` (vaultkeeper's own enforcement
   * never lets a `requirePresencePerUse` request reach this backend for that
   * operation in the first place; called directly without that flag, the
   * operation just behaves normally) are no-ops.
   */
  #resolvePresence(operation: PresenceOperation): void {
    const queue = this.#queues[operation]
    const outcome = queue === undefined ? this.#outcomes[operation] : (queue.shift() ?? 'timeout')
    if (outcome === 'refuse') {
      throw new PresenceDeclinedError(
        `Simulated presence declined for '${operation}' on '${this.type}'.`,
        this.type,
      )
    }
    if (outcome === 'timeout') {
      throw new PresenceTimeoutError(
        `Simulated presence timed out for '${operation}' on '${this.type}'.`,
        this.type,
        0,
      )
    }
  }
}
