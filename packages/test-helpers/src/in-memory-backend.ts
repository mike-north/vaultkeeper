/**
 * In-memory secret backend for testing.
 */

import type { ListableBackend } from 'vaultkeeper'

/**
 * A fully in-memory `SecretBackend` for testing.
 *
 * @remarks
 * This backend stores secrets in a plain `Map` and has no external
 * dependencies. It is suitable for unit, integration, and e2e tests.
 *
 * @public
 */
export class InMemoryBackend implements ListableBackend {
  readonly type = 'memory'
  readonly displayName = 'In-Memory Backend'
  readonly #store = new Map<string, string>()

  /** @public */
  isAvailable(): Promise<boolean> {
    return Promise.resolve(true)
  }

  /** @public */
  store(id: string, secret: string): Promise<void> {
    this.#store.set(id, secret)
    return Promise.resolve()
  }

  /** @public */
  retrieve(id: string): Promise<string> {
    const val = this.#store.get(id)
    if (val === undefined) {
      return Promise.reject(new Error(`Secret not found: ${id}`))
    }
    return Promise.resolve(val)
  }

  /** @public */
  delete(id: string): Promise<void> {
    this.#store.delete(id)
    return Promise.resolve()
  }

  /** @public */
  exists(id: string): Promise<boolean> {
    return Promise.resolve(this.#store.has(id))
  }

  /** @public */
  list(): Promise<string[]> {
    return Promise.resolve([...this.#store.keys()])
  }

  /**
   * Remove all stored secrets. Useful for test teardown.
   * @public
   */
  clear(): void {
    this.#store.clear()
  }

  /**
   * The number of secrets currently stored.
   * @public
   */
  get size(): number {
    return this.#store.size
  }
}
