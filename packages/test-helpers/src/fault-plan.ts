/**
 * Reusable deterministic fault-injection scripting for test doubles.
 */

/**
 * The deterministic fault modes a {@link FaultPlan} can script. Each is a
 * backend-agnostic scenario name — mapping a mode to a concrete typed error
 * class is the consulting double's responsibility (see e.g.
 * `InMemoryBackend.injectFault`), since the right class can depend on
 * backend-specific context (which operation, which resource namespace).
 *
 * @remarks
 * This vocabulary is intentionally shared across every test double in this
 * package, in-memory or backend-flavored (e.g. a stub CLI process faking
 * `op`/`ykman`/`security` on `PATH`): a consumer's fault-handling test should
 * read the same regardless of which double it targets.
 *
 * @public
 */
export type FaultMode =
  | 'backend-unavailable'
  | 'key-absent'
  | 'permission-denied'
  | 'session-expired'

/** Options accepted by {@link FaultPlan.inject}. */
export interface FaultOptions {
  /**
   * When `true`, the fault keeps firing on every matching call until removed
   * with {@link FaultPlan.clear}. When `false` (the default), the fault fires
   * exactly once and then clears itself, so the next identical call succeeds
   * normally.
   */
  persistent?: boolean
}

interface ArmedFault {
  mode: FaultMode
  persistent: boolean
}

/**
 * A small, backend-agnostic scripting surface for deterministic,
 * per-operation fault injection: arm a {@link FaultMode} against an operation
 * key (one-shot or persistent), then consult it before doing real work.
 *
 * @remarks
 * `FaultPlan` knows nothing about any particular backend's storage or
 * resource namespaces — it only tracks "which operation key has which mode
 * armed, and for how long." A test double (e.g. `InMemoryBackend`, or a
 * future backend-flavored double faking a CLI-backed store) holds one
 * instance per double, consults {@link FaultPlan.consume} at the top of each
 * operation, and is responsible for turning the returned {@link FaultMode}
 * into the concrete typed `vaultkeeper` error class appropriate for that
 * operation's semantics.
 *
 * `Operation` is a type parameter so each double can key faults by its own
 * operation vocabulary (e.g. `InMemoryBackend`'s `store`/`retrieve`/`sign`-ish
 * method names, or a future double's CLI subcommand names) while sharing this
 * same scripting mechanism.
 *
 * @public
 */
export class FaultPlan<Operation extends string = string> {
  readonly #faults = new Map<Operation, ArmedFault>()

  /**
   * Arm a fault for the next matching call to `operation`.
   *
   * @param operation - The operation key to fault.
   * @param mode - Which {@link FaultMode} to report when `operation` is next
   *   consumed.
   * @param options - `{ persistent: true }` to keep firing until
   *   {@link FaultPlan.clear} is called; omitted or `{ persistent: false }`
   *   (the default) fires once and then clears itself.
   */
  inject(operation: Operation, mode: FaultMode, options?: FaultOptions): void {
    this.#faults.set(operation, { mode, persistent: options?.persistent ?? false })
  }

  /**
   * Remove an armed fault for `operation`, if any. Safe to call when no fault
   * is armed.
   */
  clear(operation: Operation): void {
    this.#faults.delete(operation)
  }

  /** Remove all armed faults, regardless of mode or operation. */
  clearAll(): void {
    this.#faults.clear()
  }

  /**
   * Consult the plan for `operation`. If a fault is armed, a one-shot entry
   * is consumed (removed) before returning; a persistent entry is left
   * armed. Returns `undefined` when no fault is armed for `operation`.
   *
   * @remarks
   * This method only reports which {@link FaultMode} fired — it does not
   * throw or construct an error itself, since only the consulting double
   * knows which typed `vaultkeeper` error class fits the operation's
   * semantics (e.g. a signing operation's "key absent" is a
   * `SigningKeyNotFoundError`, while a plain secret read's is a
   * `SecretNotFoundError`).
   */
  consume(operation: Operation): FaultMode | undefined {
    const fault = this.#faults.get(operation)
    if (fault === undefined) {
      return undefined
    }
    if (!fault.persistent) {
      this.#faults.delete(operation)
    }
    return fault.mode
  }
}
