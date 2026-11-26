/**
 * Shared test helpers for backend creation.
 */

import type { SecretBackend } from '../../src/backend/types.js'
import { SecretNotFoundError } from '../../src/errors.js'

/**
 * Create a fully in-memory `SecretBackend` suitable for unit and e2e tests.
 * The returned backend has no external dependencies and starts empty.
 */
export function createInMemoryBackend(): SecretBackend {
  const store = new Map<string, string>()
  return {
    type: 'memory',
    displayName: 'In-Memory Backend',
    isAvailable: () => Promise.resolve(true),
    store: (id: string, secret: string) => {
      store.set(id, secret)
      return Promise.resolve()
    },
    retrieve: (id: string) => {
      const val = store.get(id)
      if (val === undefined) {
        // Match the SecretBackend.retrieve contract (@throws SecretNotFoundError)
        // that every real backend implementation honors, so tests exercising
        // this helper observe the same typed error callers rely on.
        return Promise.reject(new SecretNotFoundError(`Secret not found: ${id}`))
      }
      return Promise.resolve(val)
    },
    delete: (id: string) => {
      store.delete(id)
      return Promise.resolve()
    },
    exists: (id: string) => Promise.resolve(store.has(id)),
  }
}
