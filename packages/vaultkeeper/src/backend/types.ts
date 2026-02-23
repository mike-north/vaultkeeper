/**
 * Backend abstraction layer types for vaultkeeper.
 */

/**
 * Factory function for creating a SecretBackend instance.
 * @public
 */
export type BackendFactory = () => SecretBackend

/**
 * Abstraction interface for all secret storage backends.
 *
 * @remarks
 * Each backend implementation must handle its own availability check and
 * secret lifecycle (store, retrieve, delete, exists).
 *
 * @public
 */
export interface SecretBackend {
  /** Unique type identifier for this backend. */
  readonly type: string

  /** Human-readable display name for this backend. */
  readonly displayName: string

  /**
   * Check whether this backend is available on the current system.
   * @returns true if the backend can be used, false otherwise
   */
  isAvailable(): Promise<boolean>

  /**
   * Store a secret under the given id.
   * @param id - Unique identifier for the secret
   * @param secret - The secret value to store
   */
  store(id: string, secret: string): Promise<void>

  /**
   * Retrieve a secret by id.
   * @param id - Unique identifier for the secret
   * @returns The stored secret value
   * @throws SecretNotFoundError if the secret does not exist
   */
  retrieve(id: string): Promise<string>

  /**
   * Delete a secret by id.
   * @param id - Unique identifier for the secret
   * @throws SecretNotFoundError if the secret does not exist
   */
  delete(id: string): Promise<void>

  /**
   * Check whether a secret exists for the given id.
   * @param id - Unique identifier for the secret
   * @returns true if the secret exists, false otherwise
   */
  exists(id: string): Promise<boolean>
}

/**
 * Backend that can enumerate stored secret IDs.
 * @public
 */
export interface ListableBackend extends SecretBackend {
  /**
   * List IDs of all secrets managed by this backend.
   * @returns Array of secret identifiers
   */
  list(): Promise<string[]>
}

/**
 * Type guard for backends that support listing.
 * @public
 */
export function isListableBackend(backend: SecretBackend): backend is ListableBackend {
  return 'list' in backend && typeof backend.list === 'function'
}
